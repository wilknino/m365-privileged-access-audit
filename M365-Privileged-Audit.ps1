
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CompanyName,

    [string]$OutputFolder = "C:\M365-Audits",

    [string]$GraphVersion = "2.39.0"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Ensure-Module {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$RequiredVersion,
        [string]$ProbeCommand
    )

    # If the requested cmdlet is already available, do not reinstall a module.
    # This avoids unnecessary PSGallery prompts/failures when Graph submodules are
    # already present through the Microsoft.Graph meta-module.
    if ($ProbeCommand) {
        $existingCommand = Get-Command $ProbeCommand -ErrorAction SilentlyContinue
        if ($existingCommand) {
            try {
                Import-Module $existingCommand.Source -Force -ErrorAction SilentlyContinue
            } catch {}
            return
        }
    }

    $installed = Get-Module -ListAvailable -Name $Name |
        Where-Object {
            if ($RequiredVersion) { $_.Version -eq [version]$RequiredVersion }
            else { $true }
        } |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $installed) {
        Write-Host "Module $Name $RequiredVersion is not installed. Attempting PSGallery installation..." -ForegroundColor Yellow
        try {
            if ($RequiredVersion) {
                Install-Module -Name $Name -RequiredVersion $RequiredVersion -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
            } else {
                Install-Module -Name $Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
            }
        }
        catch {
            if ($ProbeCommand -and (Get-Command $ProbeCommand -ErrorAction SilentlyContinue)) {
                Write-Warning "PSGallery could not install $Name, but $ProbeCommand is already available. Continuing."
                return
            }
            throw "Required module '$Name' could not be installed or found. $($_.Exception.Message)"
        }
    }

    if ($RequiredVersion) {
        Import-Module $Name -RequiredVersion $RequiredVersion -Force -ErrorAction Stop
    } else {
        Import-Module $Name -Force -ErrorAction Stop
    }
}

function SafeString {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [string]$Value
}

function Test-EntraPremiumForSignInActivity {
    # Microsoft Graph requires Entra ID P1 or P2 for user signInActivity.
    # Detect the corresponding service plan through subscribedSkus so the
    # audit can continue on tenants that do not license Entra Premium.
    $result = [pscustomobject]@{
        Available = $false
        Reason = "Unable to determine tenant licensing."
    }

    try {
        $uri = "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,capabilityStatus,servicePlans"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($sku in @($response.value)) {
            if ([string]$sku.capabilityStatus -ne "Enabled") { continue }
            foreach ($plan in @($sku.servicePlans)) {
                $planName = [string]$plan.servicePlanName
                $provisioning = [string]$plan.provisioningStatus
                if (($planName -eq "AAD_PREMIUM" -or $planName -eq "AAD_PREMIUM_P2") -and
                    ($provisioning -eq "Success" -or [string]::IsNullOrWhiteSpace($provisioning))) {
                    return [pscustomobject]@{
                        Available = $true
                        Reason = "Entra ID P1/P2 service plan detected ($planName)."
                    }
                }
            }
        }

        return [pscustomobject]@{
            Available = $false
            Reason = "No enabled AAD_PREMIUM or AAD_PREMIUM_P2 service plan was detected."
        }
    }
    catch {
        return [pscustomobject]@{
            Available = $false
            Reason = "Could not verify tenant licensing: $($_.Exception.Message)"
        }
    }
}

function Get-PrincipalInfo {
    param(
        [string]$PrincipalId,
        [hashtable]$UserById,
        [hashtable]$GroupById,
        [hashtable]$SPById
    )

    if ([string]::IsNullOrWhiteSpace($PrincipalId)) {
        return [pscustomobject]@{
            PrincipalName = ""
            PrincipalUPN  = ""
            PrincipalType = "Unknown"
            PrincipalId   = ""
            Enabled       = ""
        }
    }

    if ($UserById.ContainsKey($PrincipalId)) {
        $u = $UserById[$PrincipalId]
        return [pscustomobject]@{
            PrincipalName = SafeString $u.DisplayName
            PrincipalUPN  = SafeString $u.UserPrincipalName
            PrincipalType = "User"
            PrincipalId   = $PrincipalId
            Enabled       = SafeString $u.AccountEnabled
        }
    }

    if ($GroupById.ContainsKey($PrincipalId)) {
        $g = $GroupById[$PrincipalId]
        return [pscustomobject]@{
            PrincipalName = SafeString $g.DisplayName
            PrincipalUPN  = SafeString $g.Mail
            PrincipalType = "Group"
            PrincipalId   = $PrincipalId
            Enabled       = ""
        }
    }

    if ($SPById.ContainsKey($PrincipalId)) {
        $sp = $SPById[$PrincipalId]
        return [pscustomobject]@{
            PrincipalName = SafeString $sp.DisplayName
            PrincipalUPN  = SafeString $sp.AppId
            PrincipalType = "Service Principal"
            PrincipalId   = $PrincipalId
            Enabled       = SafeString $sp.AccountEnabled
        }
    }

    return [pscustomobject]@{
        PrincipalName = "Unknown / Deleted Principal"
        PrincipalUPN  = ""
        PrincipalType = "Unknown"
        PrincipalId   = $PrincipalId
        Enabled       = ""
    }
}

function Get-RiskClassification {
    param(
        [string]$Role,
        [string]$PrincipalType,
        [string]$Enabled,
        [string]$AssignmentType,
        [string]$LastSignIn,
        [string]$Source,
        [string]$MFAStatus
    )

    $roleText = if ($Role) { $Role.ToLowerInvariant() } else { "" }
    $flags = New-Object System.Collections.Generic.List[string]

    if ($roleText -match "global administrator") {
        [void]$flags.Add("GLOBAL ADMIN")
    }

    $highRoles = @(
        "privileged role administrator",
        "privileged authentication administrator",
        "security administrator",
        "conditional access administrator",
        "authentication policy administrator",
        "exchange administrator",
        "sharepoint administrator",
        "user administrator",
        "application administrator",
        "cloud application administrator",
        "intune administrator",
        "directory synchronization accounts",
        "hybrid identity administrator"
    )

    foreach ($r in $highRoles) {
        if ($roleText -eq $r -or $roleText -like "*$r*") {
            [void]$flags.Add("HIGH PRIVILEGE ROLE")
            break
        }
    }

    if ($PrincipalType -eq "Service Principal") {
        [void]$flags.Add("SERVICE PRINCIPAL")
    }

    if ($PrincipalType -eq "Group") {
        [void]$flags.Add("PRIVILEGED GROUP")
    }

    if ($Enabled -eq "False") {
        [void]$flags.Add("DISABLED ACCOUNT")
    }

    if ($MFAStatus -eq "No") {
        [void]$flags.Add("NO MFA METHOD DETECTED")
    }

    if ($LastSignIn) {
        try {
            $dt = [datetime]$LastSignIn
            if ($dt -lt (Get-Date).ToUniversalTime().AddDays(-90)) {
                [void]$flags.Add("NO SIGN-IN >90 DAYS")
            }
        } catch {}
    }

    if ($AssignmentType -match "Eligible") {
        [void]$flags.Add("PIM ELIGIBLE")
    }

    if ($flags.Count -eq 0) {
        return "REVIEW"
    }

    if ($flags -contains "GLOBAL ADMIN") {
        return "CRITICAL - GLOBAL ADMIN"
    }

    if ($flags -contains "DISABLED ACCOUNT" -and
        ($flags -contains "HIGH PRIVILEGE ROLE" -or $flags -contains "GLOBAL ADMIN")) {
        return "CRITICAL - DISABLED PRIVILEGED"
    }

    if ($flags -contains "NO MFA METHOD DETECTED" -and
        ($flags -contains "HIGH PRIVILEGE ROLE" -or $flags -contains "GLOBAL ADMIN")) {
        return "HIGH - PRIVILEGED / NO MFA"
    }

    if ($flags -contains "SERVICE PRINCIPAL") {
        return "HIGH - SERVICE PRINCIPAL"
    }

    if ($flags -contains "PRIVILEGED GROUP") {
        return "HIGH - PRIVILEGED GROUP"
    }

    if ($flags -contains "NO SIGN-IN >90 DAYS") {
        return "HIGH - STALE PRIVILEGED"
    }

    return "REVIEW"
}

function Get-RiskFlags {
    param(
        [string]$Role,
        [string]$PrincipalType,
        [string]$Enabled,
        [string]$AssignmentType,
        [string]$LastSignIn,
        [string]$MFAStatus
    )

    $flags = New-Object System.Collections.Generic.List[string]
    $roleText = if ($Role) { $Role.ToLowerInvariant() } else { "" }

    if ($roleText -match "global administrator") { [void]$flags.Add("GLOBAL ADMIN") }

    $highRoles = @(
        "privileged role administrator","privileged authentication administrator",
        "security administrator","conditional access administrator",
        "authentication policy administrator","exchange administrator",
        "sharepoint administrator","user administrator","application administrator",
        "cloud application administrator","intune administrator",
        "directory synchronization accounts","hybrid identity administrator"
    )
    foreach ($r in $highRoles) {
        if ($roleText -eq $r -or $roleText -like "*$r*") {
            [void]$flags.Add("HIGH PRIVILEGE ROLE")
            break
        }
    }

    if ($PrincipalType -eq "Service Principal") { [void]$flags.Add("SERVICE PRINCIPAL") }
    if ($PrincipalType -eq "Group") { [void]$flags.Add("PRIVILEGED GROUP") }
    if ($Enabled -eq "False") { [void]$flags.Add("DISABLED ACCOUNT") }
    if ($MFAStatus -eq "No") { [void]$flags.Add("NO MFA METHOD DETECTED") }

    if ($LastSignIn) {
        try {
            if ([datetime]$LastSignIn -lt (Get-Date).ToUniversalTime().AddDays(-90)) {
                [void]$flags.Add("NO SIGN-IN >90 DAYS")
            }
        } catch {}
    }

    if ($AssignmentType -match "Eligible") { [void]$flags.Add("PIM ELIGIBLE") }

    return ($flags -join "; ")
}

$MfaCache = @{}

function Get-MFAStatusForUser {
    param([string]$UserId)

    if ($MfaCache.ContainsKey($UserId)) {
        return $MfaCache[$UserId]
    }

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $UserId -All -ErrorAction Stop
        $mfaTypes = @(
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
            "#microsoft.graph.phoneAuthenticationMethod",
            "#microsoft.graph.fido2AuthenticationMethod",
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
            "#microsoft.graph.softwareOathAuthenticationMethod",
            "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
        )

        foreach ($m in $methods) {
            $odata = $m.AdditionalProperties["@odata.type"]
            if ($odata -and $mfaTypes -contains $odata) {
                $MfaCache[$UserId] = "Yes"
                return "Yes"
            }
        }
        $MfaCache[$UserId] = "No"
        return "No"
    }
    catch {
        $MfaCache[$UserId] = "Unknown"
        return "Unknown"
    }
}

function Add-ReviewFields {
    param($Row)

    $Row | Add-Member -NotePropertyName "ReviewStatus" -NotePropertyValue "" -Force
    $Row | Add-Member -NotePropertyName "ReviewerNotes" -NotePropertyValue "" -Force
    return $Row
}

function Convert-ToExcelMatrix {
    param(
        [Parameter(Mandatory=$true)][object[]]$Data
    )

    if (-not $Data -or $Data.Count -eq 0) {
        $Data = @([pscustomobject]@{ Status = "No records returned" })
    }

    $first = $Data[0]
    $propertyNames = @($first.PSObject.Properties.Name)
    if ($propertyNames.Count -eq 0) {
        $propertyNames = @("Value")
        $Data = @([pscustomobject]@{ Value = [string]$first })
    }

    $dataItems = @($Data)
    [int]$dataCount = $dataItems.Count
    [int]$rowCount = $dataCount
    $rowCount++
    [int]$colCount = @($propertyNames).Length
    [int[]]$dims = @($rowCount, $colCount)
    $matrix = [System.Array]::CreateInstance([object], $dims)

    for ($c = 0; $c -lt $colCount; $c++) {
        $matrix[0,$c] = [string]$propertyNames[$c]
    }

    for ($r = 0; $r -lt $dataCount; $r++) {
        $item = $dataItems[$r]
        $excelRow = $r
        $excelRow++
        for ($c = 0; $c -lt $colCount; $c++) {
            $name = $propertyNames[$c]
            $prop = $item.PSObject.Properties[$name]
            $value = if ($prop) { $prop.Value } else { "" }
            if ($null -eq $value) {
                $matrix[$excelRow,$c] = ""
            }
            elseif ($value -is [System.Array] -or $value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $matrix[$excelRow,$c] = (@($value) -join "; ")
            }
            elseif ($value -is [datetime]) {
                $matrix[$excelRow,$c] = $value.ToString("yyyy-MM-dd HH:mm:ss")
            }
            else {
                $matrix[$excelRow,$c] = [string]$value
            }
        }
    }

    return @{ Matrix = $matrix; Rows = $rowCount; Columns = $colCount; Headers = $propertyNames }
}

function Write-ExcelWorksheet {
    param(
        [Parameter(Mandatory=$true)]$Workbook,
        [Parameter(Mandatory=$true)][string]$SheetName,
        [Parameter(Mandatory=$true)][object[]]$Data
    )

    $ws = $Workbook.Worksheets.Add()
    $ws.Name = $SheetName
    $converted = Convert-ToExcelMatrix -Data $Data
    $matrix = $converted.Matrix
    $rows = $converted.Rows
    $cols = $converted.Columns
    $headers = $converted.Headers

    $topLeft = $ws.Cells.Item(1,1)
    $bottomRight = $ws.Cells.Item($rows,$cols)
    $range = $ws.Range($topLeft,$bottomRight)
    $range.Value2 = $matrix

    # Header styling
    $headerRange = $ws.Range($ws.Cells.Item(1,1),$ws.Cells.Item(1,$cols))
    $headerRange.Font.Bold = $true
    $headerRange.Font.Color = 16777215
    $headerRange.Interior.Color = 6299648

    # Filter and freeze header row
    $range.AutoFilter() | Out-Null
    $ws.Activate() | Out-Null
    $ws.Range("A2").Select() | Out-Null
    $Workbook.Application.ActiveWindow.FreezePanes = $true

    # Reasonable widths; avoid giant columns
    $used = $ws.UsedRange
    $used.Columns.AutoFit() | Out-Null
    for ($c = 1; $c -le $cols; $c++) {
        if ($ws.Columns.Item($c).ColumnWidth -gt 45) {
            $ws.Columns.Item($c).ColumnWidth = 45
        }
    }

    # Identify useful review columns.
    $headerMap = @{}
    for ($c = 1; $c -le $cols; $c++) {
        $headerMap[[string]$ws.Cells.Item(1,$c).Text] = $c
    }

    $priorityCol = if ($headerMap.ContainsKey("Priority")) { $headerMap["Priority"] } else { 0 }
    $riskCol = if ($headerMap.ContainsKey("RiskFlags")) { $headerMap["RiskFlags"] } else { 0 }
    $enabledCol = if ($headerMap.ContainsKey("Enabled")) { $headerMap["Enabled"] } else { 0 }
    $reviewCol = if ($headerMap.ContainsKey("ReviewStatus")) { $headerMap["ReviewStatus"] } else { 0 }

    # Excel RGB values.
    $red = 255
    $white = 16777215
    $orange = 49407
    $black = 0
    $yellow = 65535
    $green = 5296274

    for ($r = 2; $r -le $rows; $r++) {
        if ($priorityCol -gt 0) {
            $cell = $ws.Cells.Item($r,$priorityCol)
            $v = [string]$cell.Text
            if ($v -match "CRITICAL") {
                $cell.Interior.Color = $red
                $cell.Font.Color = $white
            } elseif ($v -match "HIGH") {
                $cell.Interior.Color = $orange
                $cell.Font.Color = $black
            } elseif ($v -match "REVIEW") {
                $cell.Interior.Color = $yellow
                $cell.Font.Color = $black
            }
        }

        if ($riskCol -gt 0) {
            $cell = $ws.Cells.Item($r,$riskCol)
            $v = [string]$cell.Text
            if ($v -match "GLOBAL ADMIN|DISABLED ACCOUNT") {
                $cell.Interior.Color = $red
                $cell.Font.Color = $white
            } elseif ($v -match "NO MFA") {
                $cell.Interior.Color = $orange
                $cell.Font.Color = $black
            } elseif ($v -match "NO SIGN-IN >90 DAYS") {
                $cell.Interior.Color = $yellow
                $cell.Font.Color = $black
            }
        }

        if ($enabledCol -gt 0) {
            $cell = $ws.Cells.Item($r,$enabledCol)
            if (([string]$cell.Text) -match "^(False|0)$") {
                $cell.Interior.Color = $red
                $cell.Font.Color = $white
            }
        }

        if ($reviewCol -gt 0) {
            $cell = $ws.Cells.Item($r,$reviewCol)
            switch -Regex ([string]$cell.Text) {
                '^Keep$|^Service Account$|^Break Glass$' {
                    $cell.Interior.Color = $green
                    $cell.Font.Color = $white
                    break
                }
                '^Remove$|^Terminated$' {
                    $cell.Interior.Color = $red
                    $cell.Font.Color = $white
                    break
                }
                '^Investigate$|^Downgrade$' {
                    $cell.Interior.Color = $yellow
                    $cell.Font.Color = $black
                    break
                }
            }
        }
    }

    return $ws
}

function Export-AuditWorkbook {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][object[]]$Summary = @(),
        [Parameter(Mandatory=$false)][object[]]$AccountReview = @(),
        [Parameter(Mandatory=$false)][object[]]$AllEntra = @(),
        [Parameter(Mandatory=$false)][object[]]$PrivilegedUsers = @(),
        [Parameter(Mandatory=$false)][object[]]$PrivilegedGroups = @(),
        [Parameter(Mandatory=$false)][object[]]$GroupInheritedUsers = @(),
        [Parameter(Mandatory=$false)][object[]]$ServicePrincipals = @(),
        [Parameter(Mandatory=$false)][object[]]$ExchangeRBAC = @(),
        [Parameter(Mandatory=$false)][object[]]$ExchangeRoleGroups = @(),
        [Parameter(Mandatory=$false)][object[]]$Errors = @()
    )

    # This version deliberately uses Excel COM rather than ImportExcel/EPPlus.
    # It creates the entire workbook in one Excel session, avoiding the
    # "Could not open Excel Package" error encountered with ImportExcel 7.8.10.
    try {
        $excel = New-Object -ComObject Excel.Application -ErrorAction Stop
    }
    catch {
        throw "Microsoft Excel desktop is required for the workbook export. Excel COM could not be started: $($_.Exception.Message)"
    }

    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $workbook = $null

    try {
        $workbook = $excel.Workbooks.Add()
        # Excel requires at least one visible worksheet. Do not delete the
        # default sheet until after all audit sheets have been created.

        $sheets = @(
            @{Name="Summary"; Data=$Summary},
            @{Name="Account Review"; Data=$AccountReview},
            @{Name="All Entra Roles"; Data=$AllEntra},
            @{Name="Privileged Users"; Data=$PrivilegedUsers},
            @{Name="Privileged Groups"; Data=$PrivilegedGroups},
            @{Name="Group Inherited Users"; Data=$GroupInheritedUsers},
            @{Name="Service Principals"; Data=$ServicePrincipals},
            @{Name="Exchange RBAC"; Data=$ExchangeRBAC},
            @{Name="Exchange Role Groups"; Data=$ExchangeRoleGroups},
            @{Name="Errors"; Data=$Errors}
        )

        foreach ($item in $sheets) {
            $data = @($item.Data)
            if (-not $data -or $data.Count -eq 0) {
                $data = @([pscustomobject]@{ Status = "No records returned" })
            }
            Write-Host ("  Writing sheet: " + $item.Name + " (" + $data.Count + " rows)") -ForegroundColor DarkCyan
            Write-ExcelWorksheet -Workbook $workbook -SheetName $item.Name -Data $data | Out-Null
        }

        # Now that the audit sheets exist, remove the original blank worksheet(s).
        # Never delete the last visible worksheet.
        $defaultSheets = @()
        for ($i = $workbook.Worksheets.Count; $i -ge 1; $i--) {
            $sheet = $workbook.Worksheets.Item($i)
            if ($sheet.Name -like "Sheet*") { $defaultSheets += $sheet }
        }
        foreach ($sheet in $defaultSheets) {
            if ($workbook.Worksheets.Count -gt 1) {
                try { $sheet.Delete() } catch {}
            }
        }

        $workbook.SaveAs($Path, 51)
        $workbook.Close($true)
        $excel.Quit()
    }
    catch {
        try { if ($workbook) { $workbook.Close($false) } } catch {}
        try { if ($excel) { $excel.Quit() } } catch {}
        throw
    }
    finally {
        if ($workbook) { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) } catch {} }
        if ($excel) { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) } catch {} }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

# -------------------------------------------------------------------------
# START
# -------------------------------------------------------------------------

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$safeCompany = ($CompanyName -replace '[\\/:*?"<>|]', '_').Trim()
$OutputFile = Join-Path $OutputFolder "${safeCompany}_M365_Privileged_Audit_${timestamp}.xlsx"

Write-Section "Microsoft 365 Privileged Access Audit"
Write-Host "Company : $CompanyName" -ForegroundColor White
Write-Host "Output  : $OutputFile" -ForegroundColor White
Write-Host "READ ONLY - NO CHANGES" -ForegroundColor Green

# Modules
Write-Section "Checking required PowerShell modules"

Ensure-Module -Name "Microsoft.Graph.Authentication" -RequiredVersion $GraphVersion -ProbeCommand "Connect-MgGraph"
Ensure-Module -Name "Microsoft.Graph.Users" -RequiredVersion $GraphVersion -ProbeCommand "Get-MgUser"
Ensure-Module -Name "Microsoft.Graph.Groups" -RequiredVersion $GraphVersion -ProbeCommand "Get-MgGroup"
Ensure-Module -Name "Microsoft.Graph.Applications" -RequiredVersion $GraphVersion -ProbeCommand "Get-MgServicePrincipal"
Ensure-Module -Name "Microsoft.Graph.Identity.Governance" -RequiredVersion $GraphVersion -ProbeCommand "Get-MgRoleManagementDirectoryRoleAssignment"
Ensure-Module -Name "ExchangeOnlineManagement" -ProbeCommand "Connect-ExchangeOnline"

$Errors = New-Object System.Collections.Generic.List[object]

# -------------------------------------------------------------------------
# GRAPH
# -------------------------------------------------------------------------

Write-Section "Microsoft Graph collection"

$graphScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All",
    "Application.Read.All"
)

$signInActivityAvailable = $false
$signInActivityStatus = "Unknown"

try {
    # Reuse an existing Graph session when it already has the base scopes.
    # AuditLog.Read.All is requested only when the tenant actually has Entra
    # ID P1/P2, because signInActivity is not available on non-premium tenants.
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $requiredScopeSet = @($graphScopes | ForEach-Object { $_.ToLowerInvariant() })
    $currentScopeSet = @()
    if ($ctx -and $ctx.Scopes) {
        $currentScopeSet = @($ctx.Scopes | ForEach-Object { $_.ToLowerInvariant() })
    }

    $missingScopes = @($requiredScopeSet | Where-Object { $_ -notin $currentScopeSet })

    if (-not $ctx -or -not $ctx.TenantId -or $missingScopes.Count -gt 0) {
        if ($ctx -and $ctx.TenantId -and $missingScopes.Count -gt 0) {
            Write-Host "Existing Graph session is missing required base scopes. A single re-authentication may be required." -ForegroundColor Yellow
        }
        Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
        $ctx = Get-MgContext
    } else {
        Write-Host "Reusing existing Microsoft Graph session." -ForegroundColor Green
    }

    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Microsoft Graph authentication did not return a tenant context."
    }

    Write-Host "Connected tenant : $($ctx.TenantId)" -ForegroundColor Green
    Write-Host "Signed in as     : $($ctx.Account)" -ForegroundColor Green

    Write-Host "Checking Entra ID P1/P2 availability for sign-in activity..." -ForegroundColor Cyan
    $premiumCheck = Test-EntraPremiumForSignInActivity

    if ($premiumCheck.Available) {
        $currentScopeSet = @((Get-MgContext).Scopes | ForEach-Object { $_.ToLowerInvariant() })
        if ("auditlog.read.all" -notin $currentScopeSet) {
            Write-Host "Entra P1/P2 detected. Requesting AuditLog.Read.All for last sign-in data..." -ForegroundColor Yellow
            $fullScopes = @($graphScopes + "AuditLog.Read.All")
            Connect-MgGraph -Scopes $fullScopes -NoWelcome -ErrorAction Stop
            $ctx = Get-MgContext
        }
        $signInActivityAvailable = $true
        $signInActivityStatus = "Available - Entra ID P1/P2 detected"
        Write-Host "Sign-in activity: AVAILABLE" -ForegroundColor Green
    } else {
        $signInActivityAvailable = $false
        $signInActivityStatus = "Unavailable - $($premiumCheck.Reason)"
        Write-Warning "Sign-in activity is unavailable for this tenant. Continuing without LastSignIn data. $($premiumCheck.Reason)"
    }
}
catch {
    throw "Microsoft Graph connection/licensing check failed: $($_.Exception.Message)"
}

Write-Host "Loading users..." -ForegroundColor Cyan
if ($signInActivityAvailable) {
    try {
        $Users = @(Get-MgUser -All -Property `
            Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,CreatedDateTime,JobTitle,Department,OnPremisesSyncEnabled,SignInActivity -ErrorAction Stop)
    }
    catch {
        # Do not abort an otherwise valid privileged-access audit because
        # signInActivity is unavailable. Fall back to the normal user object.
        $signInActivityAvailable = $false
        $signInActivityStatus = "Unavailable - Graph rejected signInActivity: $($_.Exception.Message)"
        Write-Warning "Could not retrieve signInActivity. Continuing without LastSignIn data."
        try {
            $Users = @(Get-MgUser -All -Property `
                Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,CreatedDateTime,JobTitle,Department,OnPremisesSyncEnabled -ErrorAction Stop)
        }
        catch {
            throw "Failed to collect users: $($_.Exception.Message)"
        }
    }
}
else {
    try {
        $Users = @(Get-MgUser -All -Property `
            Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,CreatedDateTime,JobTitle,Department,OnPremisesSyncEnabled -ErrorAction Stop)
    }
    catch {
        throw "Failed to collect users: $($_.Exception.Message)"
    }
}
Write-Host "Users: $($Users.Count)" -ForegroundColor Green

Write-Host "Loading groups..." -ForegroundColor Cyan
try {
    $Groups = @(Get-MgGroup -All -Property `
        Id,DisplayName,Mail,MailEnabled,SecurityEnabled,GroupTypes,CreatedDateTime,OnPremisesSyncEnabled -ErrorAction Stop)
} catch {
    throw "Failed to collect groups: $($_.Exception.Message)"
}
Write-Host "Groups: $($Groups.Count)" -ForegroundColor Green

Write-Host "Loading service principals..." -ForegroundColor Cyan
try {
    $ServicePrincipals = @(Get-MgServicePrincipal -All -Property `
        Id,DisplayName,AppId,AccountEnabled,ServicePrincipalType,AppOwnerOrganizationId -ErrorAction Stop)
} catch {
    throw "Failed to collect service principals: $($_.Exception.Message)"
}
Write-Host "Service principals: $($ServicePrincipals.Count)" -ForegroundColor Green

$UserById = @{}
foreach ($u in $Users) { $UserById[$u.Id] = $u }

$GroupById = @{}
foreach ($g in $Groups) { $GroupById[$g.Id] = $g }

$SPById = @{}
foreach ($sp in $ServicePrincipals) { $SPById[$sp.Id] = $sp }

Write-Host "Loading Entra role definitions..." -ForegroundColor Cyan
$RoleDefinitions = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop)
$RoleDefById = @{}
foreach ($rd in $RoleDefinitions) { $RoleDefById[$rd.Id] = $rd }

Write-Host "Loading permanent Entra role assignments..." -ForegroundColor Cyan
$RoleAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)
Write-Host "Permanent role assignments: $($RoleAssignments.Count)" -ForegroundColor Green

Write-Host "Loading active/PIM role assignment instances..." -ForegroundColor Cyan
$ScheduleInstances = @()
try {
    $ScheduleInstances = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop)
} catch {
    $Errors.Add([pscustomobject]@{
        Area = "Entra PIM Active Assignments"
        Error = $_.Exception.Message
    })
}
Write-Host "Active/PIM instances: $($ScheduleInstances.Count)" -ForegroundColor Green

Write-Host "Loading eligible/PIM role assignments..." -ForegroundColor Cyan
$EligibilityInstances = @()
try {
    $EligibilityInstances = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction Stop)
} catch {
    $Errors.Add([pscustomobject]@{
        Area = "Entra PIM Eligible Assignments"
        Error = $_.Exception.Message
    })
}
Write-Host "Eligible instances: $($EligibilityInstances.Count)" -ForegroundColor Green

# All direct Entra role assignments
$AllEntra = New-Object System.Collections.Generic.List[object]

foreach ($a in $RoleAssignments) {
    $role = $RoleDefById[$a.RoleDefinitionId]
    $p = Get-PrincipalInfo -PrincipalId $a.PrincipalId -UserById $UserById -GroupById $GroupById -SPById $SPById

    $last = ""
    if ($p.PrincipalType -eq "User" -and $UserById[$a.PrincipalId].SignInActivity) {
        $last = SafeString $UserById[$a.PrincipalId].SignInActivity.LastSignInDateTime
    }

    $mfa = "N/A"
    if ($p.PrincipalType -eq "User") {
        $mfa = Get-MFAStatusForUser -UserId $a.PrincipalId
    }

    $roleName = SafeString $role.DisplayName
    $priority = Get-RiskClassification `
        -Role $roleName `
        -PrincipalType $p.PrincipalType `
        -Enabled (SafeString $p.Enabled) `
        -AssignmentType "Permanent" `
        -LastSignIn $last `
        -Source "Entra ID" `
        -MFAStatus $mfa

    $flags = Get-RiskFlags `
        -Role $roleName `
        -PrincipalType $p.PrincipalType `
        -Enabled (SafeString $p.Enabled) `
        -AssignmentType "Permanent" `
        -LastSignIn $last `
        -MFAStatus $mfa

    [void]$AllEntra.Add([pscustomobject]@{
        Company = $CompanyName
        Priority = $priority
        RiskFlags = $flags
        PrincipalName = $p.PrincipalName
        PrincipalUPN = $p.PrincipalUPN
        PrincipalType = $p.PrincipalType
        PrincipalId = $p.PrincipalId
        Enabled = $p.Enabled
        Role = $roleName
        RoleDescription = SafeString $role.Description
        AssignmentType = "Permanent"
        AssignmentId = SafeString $a.Id
        DirectoryScopeId = SafeString $a.DirectoryScopeId
        AppScopeId = SafeString $a.AppScopeId
        LastSignIn = $last
        MFAStatus = $mfa
        ReviewStatus = ""
        ReviewerNotes = ""
    })
}

foreach ($a in $ScheduleInstances) {
    $role = $RoleDefById[$a.RoleDefinitionId]
    $p = Get-PrincipalInfo -PrincipalId $a.PrincipalId -UserById $UserById -GroupById $GroupById -SPById $SPById

    $last = ""
    if ($p.PrincipalType -eq "User" -and $UserById[$a.PrincipalId].SignInActivity) {
        $last = SafeString $UserById[$a.PrincipalId].SignInActivity.LastSignInDateTime
    }

    $mfa = "N/A"
    if ($p.PrincipalType -eq "User") { $mfa = Get-MFAStatusForUser -UserId $a.PrincipalId }

    $roleName = SafeString $role.DisplayName
    $priority = Get-RiskClassification -Role $roleName -PrincipalType $p.PrincipalType -Enabled (SafeString $p.Enabled) -AssignmentType "PIM Active" -LastSignIn $last -Source "Entra ID PIM" -MFAStatus $mfa
    $flags = Get-RiskFlags -Role $roleName -PrincipalType $p.PrincipalType -Enabled (SafeString $p.Enabled) -AssignmentType "PIM Active" -LastSignIn $last -MFAStatus $mfa

    [void]$AllEntra.Add([pscustomobject]@{
        Company = $CompanyName
        Priority = $priority
        RiskFlags = $flags
        PrincipalName = $p.PrincipalName
        PrincipalUPN = $p.PrincipalUPN
        PrincipalType = $p.PrincipalType
        PrincipalId = $p.PrincipalId
        Enabled = $p.Enabled
        Role = $roleName
        RoleDescription = SafeString $role.Description
        AssignmentType = "PIM Active"
        AssignmentId = SafeString $a.Id
        DirectoryScopeId = SafeString $a.DirectoryScopeId
        AppScopeId = SafeString $a.AppScopeId
        LastSignIn = $last
        MFAStatus = $mfa
        ReviewStatus = ""
        ReviewerNotes = ""
    })
}

foreach ($a in $EligibilityInstances) {
    $role = $RoleDefById[$a.RoleDefinitionId]
    $p = Get-PrincipalInfo -PrincipalId $a.PrincipalId -UserById $UserById -GroupById $GroupById -SPById $SPById

    $last = ""
    if ($p.PrincipalType -eq "User" -and $UserById[$a.PrincipalId].SignInActivity) {
        $last = SafeString $UserById[$a.PrincipalId].SignInActivity.LastSignInDateTime
    }

    $mfa = "N/A"
    if ($p.PrincipalType -eq "User") { $mfa = Get-MFAStatusForUser -UserId $a.PrincipalId }

    $roleName = SafeString $role.DisplayName
    $priority = Get-RiskClassification -Role $roleName -PrincipalType $p.PrincipalType -Enabled (SafeString $p.Enabled) -AssignmentType "PIM Eligible" -LastSignIn $last -Source "Entra ID PIM" -MFAStatus $mfa
    $flags = Get-RiskFlags -Role $roleName -PrincipalType $p.PrincipalType -Enabled (SafeString $p.Enabled) -AssignmentType "PIM Eligible" -LastSignIn $last -MFAStatus $mfa

    [void]$AllEntra.Add([pscustomobject]@{
        Company = $CompanyName
        Priority = $priority
        RiskFlags = $flags
        PrincipalName = $p.PrincipalName
        PrincipalUPN = $p.PrincipalUPN
        PrincipalType = $p.PrincipalType
        PrincipalId = $p.PrincipalId
        Enabled = $p.Enabled
        Role = $roleName
        RoleDescription = SafeString $role.Description
        AssignmentType = "PIM Eligible"
        AssignmentId = SafeString $a.Id
        DirectoryScopeId = SafeString $a.DirectoryScopeId
        AppScopeId = SafeString $a.AppScopeId
        LastSignIn = $last
        MFAStatus = $mfa
        ReviewStatus = ""
        ReviewerNotes = ""
    })
}

# Privileged users and groups
$PrivilegedUsers = @(
    $AllEntra |
    Where-Object { $_.PrincipalType -eq "User" } |
    Sort-Object PrincipalUPN,Role,AssignmentType -Unique
)

$PrivilegedGroups = @(
    $AllEntra |
    Where-Object { $_.PrincipalType -eq "Group" } |
    Sort-Object PrincipalName,Role,AssignmentType -Unique
)

$PrivilegedSPs = @(
    $AllEntra |
    Where-Object { $_.PrincipalType -eq "Service Principal" } |
    Sort-Object PrincipalName,Role,AssignmentType -Unique
)

# Group inheritance
Write-Host "Resolving users inheriting privileged access through groups..." -ForegroundColor Cyan
$GroupBasedUsers = New-Object System.Collections.Generic.List[object]

foreach ($g in $PrivilegedGroups) {
    try {
        $members = @(Get-MgGroupTransitiveMemberAsUser -GroupId $g.PrincipalId -All -ErrorAction Stop)
        foreach ($member in $members) {
            $u = $UserById[$member.Id]
            if (-not $u) { continue }

            $mfa = Get-MFAStatusForUser -UserId $u.Id
            $last = ""
            if ($u.SignInActivity) { $last = SafeString $u.SignInActivity.LastSignInDateTime }

            $priority = Get-RiskClassification -Role $g.Role -PrincipalType "User" -Enabled (SafeString $u.AccountEnabled) -AssignmentType "Inherited through group" -LastSignIn $last -Source "Entra Group" -MFAStatus $mfa
            $flags = Get-RiskFlags -Role $g.Role -PrincipalType "User" -Enabled (SafeString $u.AccountEnabled) -AssignmentType "Inherited through group" -LastSignIn $last -MFAStatus $mfa

            [void]$GroupBasedUsers.Add([pscustomobject]@{
                Company = $CompanyName
                Priority = $priority
                RiskFlags = $flags
                User = SafeString $u.DisplayName
                UserUPN = SafeString $u.UserPrincipalName
                UserId = SafeString $u.Id
                Enabled = SafeString $u.AccountEnabled
                MFAStatus = $mfa
                LastSignIn = $last
                PrivilegedGroup = $g.PrincipalName
                PrivilegedGroupId = $g.PrincipalId
                Role = $g.Role
                AssignmentType = "Inherited through group"
                ReviewStatus = ""
                ReviewerNotes = ""
            })
        }
    }
    catch {
        $Errors.Add([pscustomobject]@{
            Area = "Group inheritance"
            Error = "Group '$($g.PrincipalName)' / $($_.Exception.Message)"
        })
    }
}

# Account Review: direct users + group-inherited users
$AccountReview = New-Object System.Collections.Generic.List[object]

foreach ($r in $PrivilegedUsers) {
    [void]$AccountReview.Add([pscustomobject]@{
        Company = $CompanyName
        Priority = $r.Priority
        RiskFlags = $r.RiskFlags
        Account = $r.PrincipalName
        UPN = $r.PrincipalUPN
        AccountType = "User"
        Enabled = $r.Enabled
        MFAStatus = $r.MFAStatus
        LastSignIn = $r.LastSignIn
        AccessSource = "Direct Entra role"
        PrivilegedRole = $r.Role
        AssignmentType = $r.AssignmentType
        PrivilegedGroup = ""
        ReviewStatus = ""
        ReviewerNotes = ""
    })
}

foreach ($r in $GroupBasedUsers) {
    [void]$AccountReview.Add([pscustomobject]@{
        Company = $CompanyName
        Priority = $r.Priority
        RiskFlags = $r.RiskFlags
        Account = $r.User
        UPN = $r.UserUPN
        AccountType = "User"
        Enabled = $r.Enabled
        MFAStatus = $r.MFAStatus
        LastSignIn = $r.LastSignIn
        AccessSource = "Inherited through group"
        PrivilegedRole = $r.Role
        AssignmentType = $r.AssignmentType
        PrivilegedGroup = $r.PrivilegedGroup
        ReviewStatus = ""
        ReviewerNotes = ""
    })
}

# Service principals
$ServicePrincipalReview = @(
    $PrivilegedSPs | ForEach-Object {
        [pscustomobject]@{
            Company = $CompanyName
            Priority = $_.Priority
            RiskFlags = $_.RiskFlags
            ServicePrincipal = $_.PrincipalName
            AppId = $_.PrincipalUPN
            ObjectId = $_.PrincipalId
            Enabled = $_.Enabled
            Role = $_.Role
            AssignmentType = $_.AssignmentType
            ReviewStatus = ""
            ReviewerNotes = ""
        }
    }
)

# Account summary
$AccountSummary = @(
    $Users | ForEach-Object {
        $last = ""
        if ($_.SignInActivity) { $last = SafeString $_.SignInActivity.LastSignInDateTime }

        [pscustomobject]@{
            Company = $CompanyName
            DisplayName = SafeString $_.DisplayName
            UserPrincipalName = SafeString $_.UserPrincipalName
            AccountEnabled = SafeString $_.AccountEnabled
            UserType = SafeString $_.UserType
            JobTitle = SafeString $_.JobTitle
            Department = SafeString $_.Department
            OnPremisesSyncEnabled = SafeString $_.OnPremisesSyncEnabled
            LastSignIn = $last
            PrivilegedDirect = if ($PrivilegedUsers.PrincipalId -contains $_.Id) { "Yes" } else { "No" }
            PrivilegedViaGroup = if ($GroupBasedUsers.UserId -contains $_.Id) { "Yes" } else { "No" }
        }
    }
)

# -------------------------------------------------------------------------
# Disconnect Graph BEFORE connecting to Exchange
# -------------------------------------------------------------------------
# Graph and Exchange Online use separate authentication sessions. A normal
# run therefore requires one Graph sign-in and one Exchange sign-in. This
# disconnect is intentional because the Exchange module can conflict with
# Microsoft Graph assemblies when both sessions are kept loaded.
Write-Host "Switching from Microsoft Graph to Exchange Online. You may see a separate Exchange sign-in." -ForegroundColor Yellow

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

# -------------------------------------------------------------------------
# EXCHANGE ONLINE
# -------------------------------------------------------------------------

Write-Section "Exchange Online collection"

$ExchangeAssignments = @()
$ExchangeRoleGroups = New-Object System.Collections.Generic.List[object]

try {
    Connect-ExchangeOnline -DisableWAM -ShowBanner:$false -ErrorAction Stop
    Write-Host "Connected to Exchange Online." -ForegroundColor Green
}
catch {
    throw "Exchange Online connection failed: $($_.Exception.Message)"
}

try {
    Write-Host "Loading Exchange RBAC assignments..." -ForegroundColor Cyan

    # IMPORTANT: Get-ManagementRoleAssignment does NOT support -ResultSize.
    $rawExchange = @(Get-ManagementRoleAssignment -Delegating $false -ErrorAction Stop)

    foreach ($a in $rawExchange) {
        $assignee = SafeString $a.RoleAssigneeName
        $roleName = SafeString $a.Role

        $priority = "REVIEW"
        $flags = ""

        if ($assignee -match "Organization Management|Recipient Management|Security Administrator|Compliance Management") {
            $priority = "HIGH - PRIVILEGED ROLE GROUP"
            $flags = "PRIVILEGED EXCHANGE ROLE GROUP"
        }

        $ExchangeAssignments += [pscustomobject]@{
            Company = $CompanyName
            Priority = $priority
            RiskFlags = $flags
            Role = $roleName
            RoleAssigneeName = $assignee
            RoleAssigneeType = SafeString $a.RoleAssigneeType
            AssignmentMethod = SafeString $a.AssignmentMethod
            Enabled = SafeString $a.Enabled
            CustomResourceScope = SafeString $a.CustomResourceScope
            RecipientWriteScope = SafeString $a.RecipientWriteScope
            ConfigWriteScope = SafeString $a.ConfigWriteScope
            ExclusiveRecipientWriteScope = SafeString $a.ExclusiveRecipientWriteScope
            ExclusiveConfigWriteScope = SafeString $a.ExclusiveConfigWriteScope
            ReviewStatus = ""
            ReviewerNotes = ""
        }
    }

    Write-Host "Exchange RBAC assignments: $($ExchangeAssignments.Count)" -ForegroundColor Green
}
catch {
    $Errors.Add([pscustomobject]@{
        Area = "Exchange RBAC"
        Error = $_.Exception.Message
    })
}

try {
    Write-Host "Loading Exchange role groups..." -ForegroundColor Cyan

    $roleGroups = @(Get-RoleGroup -ErrorAction Stop)

    foreach ($rg in $roleGroups) {
        $membersText = ""
        try {
            $members = @(Get-RoleGroupMember -Identity $rg.Identity -ErrorAction Stop)
            $memberNames = @($members | ForEach-Object { SafeString $_.Name })
            $membersText = $memberNames -join "; "
        }
        catch {
            $membersText = "ERROR: $($_.Exception.Message)"
        }

        $priority = "REVIEW"
        $flags = ""

        if ($rg.Name -match "Organization Management|Recipient Management|Compliance Management|Security") {
            $priority = "HIGH - PRIVILEGED ROLE GROUP"
            $flags = "PRIVILEGED EXCHANGE ROLE GROUP"
        }

        [void]$ExchangeRoleGroups.Add([pscustomobject]@{
            Company = $CompanyName
            Priority = $priority
            RiskFlags = $flags
            RoleGroup = SafeString $rg.Name
            Description = SafeString $rg.Description
            ManagedBy = SafeString (($rg.ManagedBy | ForEach-Object { $_.ToString() }) -join "; ")
            Members = $membersText
            RoleAssignmentPolicy = SafeString $rg.RoleAssignmentPolicy
            ReviewStatus = ""
            ReviewerNotes = ""
        })
    }

    Write-Host "Exchange role groups: $($ExchangeRoleGroups.Count)" -ForegroundColor Green
}
catch {
    $Errors.Add([pscustomobject]@{
        Area = "Exchange Role Groups"
        Error = $_.Exception.Message
    })
}

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

# -------------------------------------------------------------------------
# SUMMARY
# -------------------------------------------------------------------------

$CriticalCount = @($AccountReview | Where-Object Priority -like "CRITICAL*").Count
$HighCount = @($AccountReview | Where-Object Priority -like "HIGH*").Count
$ReviewCount = @($AccountReview | Where-Object Priority -eq "REVIEW").Count
$DisabledPrivileged = @($AccountReview | Where-Object Enabled -eq "False").Count
$NoMFA = @($AccountReview | Where-Object MFAStatus -eq "No").Count

$Summary = @(
    [pscustomobject]@{ Company=$CompanyName; Metric="Total Entra users"; Count=$Users.Count; Action="Reference" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Total groups"; Count=$Groups.Count; Action="Reference" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Service principals"; Count=$ServicePrincipals.Count; Action="Reference" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Permanent Entra role assignments"; Count=$RoleAssignments.Count; Action="Review access" }
    [pscustomobject]@{ Company=$CompanyName; Metric="PIM active assignments"; Count=$ScheduleInstances.Count; Action="Review access" }
    [pscustomobject]@{ Company=$CompanyName; Metric="PIM eligible assignments"; Count=$EligibilityInstances.Count; Action="Review access" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Direct privileged users"; Count=$PrivilegedUsers.Count; Action="Review each user" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Users with group-inherited privileged access"; Count=$GroupBasedUsers.Count; Action="Review each user" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Privileged service principals"; Count=$PrivilegedSPs.Count; Action="Review each app/service principal" }
    [pscustomobject]@{ Company=$CompanyName; Metric="CRITICAL findings"; Count=$CriticalCount; Action="CHECK FIRST" }
    [pscustomobject]@{ Company=$CompanyName; Metric="HIGH findings"; Count=$HighCount; Action="CHECK FIRST" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Review findings"; Count=$ReviewCount; Action="Review" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Disabled privileged accounts"; Count=$DisabledPrivileged; Action="Verify terminated users" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Privileged users with no MFA method detected"; Count=$NoMFA; Action="Verify MFA" }
    [pscustomobject]@{ Company=$CompanyName; Metric="Sign-in activity"; Count=$signInActivityStatus; Action=if($signInActivityAvailable){"LastSignIn collected"}else{"LastSignIn not available; review licensing"} }
    [pscustomobject]@{ Company=$CompanyName; Metric="Collection errors"; Count=$Errors.Count; Action=if($Errors.Count -gt 0){"FIX BEFORE USING REPORT"}else{"None"} }
)

# -------------------------------------------------------------------------
# EXPORT
# -------------------------------------------------------------------------

Write-Section "Creating Excel workbook"

if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
}

Export-AuditWorkbook `
    -Path $OutputFile `
    -Summary @($Summary) `
    -AccountReview @($AccountReview.ToArray()) `
    -AllEntra @($AllEntra.ToArray()) `
    -PrivilegedUsers @($PrivilegedUsers) `
    -PrivilegedGroups @($PrivilegedGroups) `
    -GroupInheritedUsers @($GroupBasedUsers.ToArray()) `
    -ServicePrincipals @($ServicePrincipalReview) `
    -ExchangeRBAC @($ExchangeAssignments) `
    -ExchangeRoleGroups @($ExchangeRoleGroups.ToArray()) `
    -Errors @($Errors.ToArray())

Write-Section "AUDIT COMPLETE"

Write-Host "Excel file:" -ForegroundColor Green
Write-Host $OutputFile -ForegroundColor White

Write-Host ""
Write-Host "Review these sheets FIRST:" -ForegroundColor Yellow
Write-Host "  1. Account Review       <- MAIN REVIEW SHEET" -ForegroundColor Yellow
Write-Host "  2. Summary              <- FINDING COUNTS" -ForegroundColor Yellow
Write-Host "  3. Privileged Users     <- DIRECT ADMIN ACCESS" -ForegroundColor Yellow
Write-Host "  4. Group Inherited Users<- ACCESS THROUGH GROUPS" -ForegroundColor Yellow
Write-Host "  5. Service Principals   <- APPLICATION ACCESS" -ForegroundColor Yellow
Write-Host "  6. Exchange RBAC        <- EXCHANGE ADMIN ACCESS" -ForegroundColor Yellow
Write-Host "  7. Errors               <- MUST BE EMPTY BEFORE FINAL REVIEW" -ForegroundColor Yellow

if ($Errors.Count -gt 0) {
    Write-Warning "The audit completed with $($Errors.Count) collection error(s). Review the Errors worksheet before relying on the report."
} else {
    Write-Host "No collection errors were recorded." -ForegroundColor Green
}

Write-Host ""
Write-Host "Suggested ReviewStatus values:" -ForegroundColor Cyan
Write-Host "Keep | Remove | Downgrade | Investigate | Terminated | Service Account | Break Glass" -ForegroundColor White
