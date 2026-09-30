# Review Workflow

The workbook is intended to support a human review and approval process.

1. Start with **Account Review**.
2. Validate disabled or terminated privileged accounts against HR/offboarding records.
3. Review Global Administrator accounts and confirm the business need for each.
4. Review privileged accounts with no MFA method detected.
5. Review stale privileged accounts based on available sign-in activity.
6. Validate privileged groups and group-inherited access.
7. Review privileged service principals and confirm application ownership and required permissions.
8. Review Exchange RBAC assignments and role groups.
9. Investigate any entries on the **Errors** sheet before treating missing data as absence of access.

The audit script does not remove permissions or disable accounts.
