# Permissions

The script uses delegated Microsoft Graph access. Required scopes are requested at runtime and may require administrator consent.

| Scope | Purpose |
|---|---|
| Directory.Read.All | Read directory objects and directory role information |
| RoleManagement.Read.Directory | Read directory role assignments/definitions |
| RoleEligibilitySchedule.Read.Directory | Read PIM eligibility data when available |
| RoleAssignmentSchedule.Read.Directory | Read active PIM assignment data when available |
| User.Read.All | Read user properties |
| UserAuthenticationMethod.Read.All | Read authentication-method information for MFA review |
| Group.Read.All | Read groups |
| GroupMember.Read.All | Resolve group membership and inherited access |
| Application.Read.All | Read service principals/applications |
| AuditLog.Read.All | Read sign-in activity where the tenant supports it |

Exchange Online is connected separately through ExchangeOnlineManagement for read-only RBAC queries.
