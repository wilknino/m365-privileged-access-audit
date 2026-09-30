# M365 Privileged Access Audit

A read-only PowerShell audit tool for reviewing Microsoft 365 privileged access across multiple tenants.

The report is designed to make privileged-account cleanup easier by consolidating Entra ID directory roles, PIM assignments, privileged groups, group-inherited access, service principals, and Exchange Online RBAC into one Excel workbook with visual review flags.

> **Read-only:** The audit does not disable users, remove roles, change group membership, modify PIM, or change Exchange permissions.

## What it audits

- Microsoft Entra directory roles and permanent role assignments
- PIM active and eligible role assignments when available
- Privileged access inherited through groups
- Privileged service principals / applications
- MFA authentication methods for privileged users, when permission/data is available
- Exchange Online RBAC assignments and role groups
- Last sign-in activity when the tenant supports the required Entra licensing and permission
- Review-priority flags for items such as Global Administrator, disabled privileged accounts, missing MFA methods, stale privileged accounts, privileged groups, and service principals

## Excel report

The workbook contains:

1. **Summary** — audit totals and environment information
2. **Account Review** — primary review worksheet
3. **All Entra Roles** — all collected Entra role assignments
4. **Privileged Users** — users with privileged Entra access
5. **Privileged Groups** — groups holding privileged access
6. **Group Inherited Users** — users inheriting privileged access through groups
7. **Service Principals** — privileged application/service-principal access
8. **Exchange RBAC** — Exchange role assignments
9. **Exchange Role Groups** — Exchange role groups and members
10. **Errors** — collection errors and warnings

The workbook uses cell highlighting to make common review conditions easier to find. These are **review flags**, not findings of malicious activity.

## Requirements

- Windows PowerShell 5.1
- Microsoft Excel desktop (required because the workbook is generated through Excel COM)
- Internet access to Microsoft Graph and Exchange Online
- Microsoft Graph PowerShell modules compatible with the script (the script is pinned to Graph `2.39.0` by default)
- ExchangeOnlineManagement PowerShell module
- A Microsoft Entra account with sufficient permissions/consent for the requested Graph scopes and Exchange RBAC read access

## Microsoft Graph delegated scopes

The script requests:

- `Directory.Read.All`
- `RoleManagement.Read.Directory`
- `RoleEligibilitySchedule.Read.Directory`
- `RoleAssignmentSchedule.Read.Directory`
- `User.Read.All`
- `UserAuthenticationMethod.Read.All`
- `Group.Read.All`
- `GroupMember.Read.All`
- `Application.Read.All`
- `AuditLog.Read.All` when sign-in activity is supported by the tenant

The tenant administrator may need to grant consent. The sign-in-activity portion depends on tenant capabilities/licensing; when unavailable, the audit is designed to continue and identify the limitation instead of treating the entire audit as failed.

## Usage

Open an elevated Windows PowerShell session if your environment requires it, then:

```powershell
cd C:\M365-Audit
Unblock-File .\M365-Privileged-Audit.ps1
.\M365-Privileged-Audit.ps1 -CompanyName "Example Company"
```

By default, reports are written to:

```text
C:\M365-Audits
```

You can change the output folder:

```powershell
.\M365-Privileged-Audit.ps1 -CompanyName "Example Company" -OutputFolder "C:\Reports"
```

## Recommended review workflow

Use **Account Review** first. Validate terminated/disabled accounts, confirm which Global Administrator accounts are genuinely required, review privileged users without MFA, review stale privileged accounts, and validate privileged service principals before making any changes.

The script does **not** make those changes automatically. Treat the workbook as an input to your organization's normal approval and change-management process.

## Multi-tenant use

The same script can be used against multiple Microsoft 365 tenants. Each run authenticates to the tenant currently selected in Microsoft Graph.

Example:

```powershell
.\M365-Privileged-Audit.ps1 -CompanyName "Company A"
.\M365-Privileged-Audit.ps1 -CompanyName "Company B"
.\M365-Privileged-Audit.ps1 -CompanyName "Company C"
```

## Security and privacy

Do not commit audit output, tenant IDs, usernames, tokens, exported sign-in logs, or other customer data to a public repository.

The repository contains the **tool**, not customer reports.

For customer environments, follow the applicable privacy, security, retention, and change-control requirements.

## Scope limitations

This project focuses on the privileged-access areas collected by the script. It is not a complete inventory of every Microsoft 365 permission surface. For example, SharePoint site permissions, Teams membership/ownership, mailbox-folder delegates, Azure resource RBAC, and application-specific authorization may require separate audits.

## License

MIT License. See [LICENSE](LICENSE).
