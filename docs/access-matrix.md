# Access matrix

Generated from the role catalog, the scope and management strategy registries and the permission each endpoint declares. Do not edit it by hand: a test regenerates it in memory and fails when this file differs.

Regenerate it with `UPDATE_ACCESS_MATRIX=1 dotnet test --project tests/Rbac.IntegrationTests --filter "FullyQualifiedName~AccessMatrixDocumentTests"` (see the README for the PowerShell form).

It shows **role defaults** only. Per-user grants and revokes, and edits made through the administration API, are not reflected here. Every tenant starts from these defaults and edits its own copy; `GET /api/v1/access-matrix` returns the same matrix computed from the caller's tenant's stored role defaults.

## Families and strategies

| Family | Roles | Booking scope | User scope | Management |
| --- | --- | --- | --- | --- |
| System | `system-admin` | `SystemScope` | `SystemUserScope` | `CrossAccountRoleManagement` |
| Finance | `finance-officer` | `FinanceScope` | `SelfUserScope` | `DenyAllRoleManagement` |
| Internal | `internal-admin`, `internal-staff` | `InternalScope` | `InternalUserScope` | `CrossAccountRoleManagement` |
| Corporate | `corporate-admin`, `corporate-staff` | `CorporateScope` | `CorporateUserScope` | `AccountRoleManagement` |
| Agency | `agency-admin`, `agency-staff` | `AgencyScope` | `AgencyUserScope` | `AccountRoleManagement` |
| Viewer | `report-viewer` | `ViewerScope` | `SelfUserScope` | `DenyAllRoleManagement` |
| (not a family) | `customer` | `CustomerScope` | `SelfUserScope` | `DenyAllRoleManagement` |
| (not a family) | `anonymous` | `NoAccessScope` | `NoAccessScope` | `DenyAllRoleManagement` |

## What each strategy does

- `AccountRoleManagement`: Manages staff inside their own account. Only the founding admin creates or promotes admins, and nobody inside the account can delete or demote the founding admin.
- `AgencyScope`: The caller's agency: all of it for an agency admin or with `bookings.view-all-agency`, otherwise only their own bookings. No agency, no rows.
- `AgencyUserScope`: The users of the caller's own agency.
- `CorporateScope`: The caller's corporate account: all of it for a corporate admin or with `bookings.view-all-corporate`, otherwise only their own bookings. No corporate account, no rows.
- `CorporateUserScope`: The users of the caller's own corporate account.
- `CrossAccountRoleManagement`: May manage, and act as, users of strictly lower standing anywhere in the tenant. Creates only roles listed for their role.
- `CustomerScope`: The customer's own bookings.
- `DenyAllRoleManagement`: Manages nobody.
- `FinanceScope`: Bookings in refund-related statuses (RefundRequested, Refunded); the whole tenant when the caller also holds `reports.view`.
- `InternalScope`: Bookings written by internal staff and guest bookings in the tenant, never agency- or corporate-owned ones.
- `InternalUserScope`: Every user in the caller's tenant except members of the system family.
- `NoAccessScope`: Nothing. The fail-closed fallback for anonymous callers and anything that cannot be resolved.
- `SelfUserScope`: Only the caller's own user record.
- `SystemScope`: Every booking in the caller's tenant.
- `SystemUserScope`: Every user in the caller's tenant.
- `ViewerScope`: No booking rows.

## Endpoints and the permission each requires

| Method | Path | Required permission | Rows reached through |
| --- | --- | --- | --- |
| GET | `/api/v1/bookings` | `bookings.read` | Booking scope |
| POST | `/api/v1/bookings` | `bookings.create` | Booking scope |
| GET | `/api/v1/bookings/{id}` | `bookings.read` | Booking scope |
| POST | `/api/v1/bookings/{id}/cancel` | `bookings.cancel` | Booking scope |
| GET | `/api/v1/users` | `users.read` | User scope |
| POST | `/api/v1/users` | `users.create` | User scope |
| GET | `/api/v1/users/{id}` | `users.read` | User scope |
| DELETE | `/api/v1/users/{id}` | `users.manage` | User scope |
| GET | `/api/v1/users/{id}/permissions` | `permissions.view` | User scope |
| PUT | `/api/v1/users/{id}/permissions` | `users.manage` | User scope |
| PUT | `/api/v1/users/{id}/role` | `users.manage` | User scope |
| GET | `/api/v1/access-matrix` | `access-matrix.view` | - |
| GET | `/api/v1/audit` | `audit.view` | - |
| GET | `/api/v1/permissions` | `permissions.view` | - |
| GET | `/api/v1/roles` | `permissions.view` | - |
| GET | `/api/v1/roles/{key}` | `permissions.view` | - |
| PUT | `/api/v1/roles/{key}/permissions` | `roles.manage-permissions` | - |

Every other endpoint is either anonymous (health, the demo token issuer) or open to any authenticated caller (`/api/v1/me`, the OpenAPI document).

## Bookings

`yes` when the role holds the required permission by default. The scope column says which rows that permission reaches (Booking).

| Subject | Scope | GET /bookings | POST /bookings | GET /bookings/{id} | POST /bookings/{id}/cancel |
| --- | --- | --- | --- | --- | --- |
| `system-admin` | `SystemScope` | yes | yes | yes | yes |
| `finance-officer` | `FinanceScope` | yes | - | yes | - |
| `internal-admin` | `InternalScope` | yes | yes | yes | yes |
| `internal-staff` | `InternalScope` | yes | yes | yes | yes |
| `corporate-admin` | `CorporateScope` | yes | yes | yes | yes |
| `corporate-staff` | `CorporateScope` | yes | yes | yes | yes |
| `agency-admin` | `AgencyScope` | yes | yes | yes | yes |
| `agency-staff` | `AgencyScope` | yes | yes | yes | yes |
| `report-viewer` | `ViewerScope` | - | - | - | - |
| `customer` | `CustomerScope` | yes | yes | yes | yes |
| `anonymous` | `NoAccessScope` | - | - | - | - |

## Users

`yes` when the role holds the required permission by default. The scope column says which rows that permission reaches (User).

| Subject | Scope | GET /users | POST /users | GET /users/{id} | DELETE /users/{id} | GET /users/{id}/permissions | PUT /users/{id}/permissions | PUT /users/{id}/role |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `system-admin` | `SystemUserScope` | yes | yes | yes | yes | yes | yes | yes |
| `finance-officer` | `SelfUserScope` | - | - | - | - | - | - | - |
| `internal-admin` | `InternalUserScope` | yes | yes | yes | yes | yes | yes | yes |
| `internal-staff` | `InternalUserScope` | - | - | - | - | - | - | - |
| `corporate-admin` | `CorporateUserScope` | yes | yes | yes | yes | yes | yes | yes |
| `corporate-staff` | `CorporateUserScope` | - | - | - | - | - | - | - |
| `agency-admin` | `AgencyUserScope` | yes | yes | yes | yes | yes | yes | yes |
| `agency-staff` | `AgencyUserScope` | - | - | - | - | - | - | - |
| `report-viewer` | `SelfUserScope` | - | - | - | - | - | - | - |
| `customer` | `SelfUserScope` | - | - | - | - | - | - | - |
| `anonymous` | `NoAccessScope` | - | - | - | - | - | - | - |

## Administration

`yes` when the role holds the required permission by default.

| Subject | GET /access-matrix | GET /audit | GET /permissions | GET /roles | GET /roles/{key} | PUT /roles/{key}/permissions |
| --- | --- | --- | --- | --- | --- | --- |
| `system-admin` | yes | yes | yes | yes | yes | yes |
| `finance-officer` | - | - | - | - | - | - |
| `internal-admin` | - | yes | yes | yes | yes | - |
| `internal-staff` | - | - | - | - | - | - |
| `corporate-admin` | - | - | yes | yes | yes | - |
| `corporate-staff` | - | - | - | - | - | - |
| `agency-admin` | - | - | yes | yes | yes | - |
| `agency-staff` | - | - | - | - | - | - |
| `report-viewer` | - | - | - | - | - | - |
| `customer` | - | - | - | - | - | - |
| `anonymous` | - | - | - | - | - | - |

## Creation graph

Who may create which roles. Account-bound roles are created inside the creator's own account only, and only the founding admin of an account creates further admins.

| Role | Tier | Can create |
| --- | --- | --- |
| `system-admin` | admin | `finance-officer`, `internal-admin`, `internal-staff`, `corporate-admin`, `corporate-staff`, `agency-admin`, `agency-staff`, `report-viewer` |
| `finance-officer` | staff | - |
| `internal-admin` | admin | `internal-staff`, `corporate-admin`, `agency-admin`, `report-viewer` |
| `internal-staff` | staff | - |
| `corporate-admin` | admin | `corporate-admin`, `corporate-staff` |
| `corporate-staff` | staff | - |
| `agency-admin` | admin | `agency-admin`, `agency-staff` |
| `agency-staff` | staff | - |
| `report-viewer` | staff | - |

## Permissions

| Permission | Description | Reserved | Held by default by |
| --- | --- | --- | --- |
| `bookings.read` | Read bookings inside the caller's scope | - | `system-admin`, `finance-officer`, `internal-admin`, `internal-staff`, `corporate-admin`, `corporate-staff`, `agency-admin`, `agency-staff`, `customer` |
| `bookings.create` | Create bookings | - | `system-admin`, `internal-admin`, `internal-staff`, `corporate-admin`, `corporate-staff`, `agency-admin`, `agency-staff`, `customer` |
| `bookings.cancel` | Cancel bookings inside the caller's scope | - | `system-admin`, `internal-admin`, `internal-staff`, `corporate-admin`, `corporate-staff`, `agency-admin`, `agency-staff`, `customer` |
| `bookings.view-all-agency` | See every booking of the caller's agency, not only their own | - | `agency-admin` |
| `bookings.view-all-corporate` | See every booking of the caller's corporate account, not only their own | - | `corporate-admin` |
| `reports.view` | View reports | - | `system-admin`, `internal-admin`, `report-viewer` |
| `users.read` | List and read users inside the caller's scope | - | `system-admin`, `internal-admin`, `corporate-admin`, `agency-admin` |
| `users.create` | Create users the caller's role may create | - | `system-admin`, `internal-admin`, `corporate-admin`, `agency-admin` |
| `users.manage` | Change roles, delete users and edit their permissions inside the caller's management scope | - | `system-admin`, `internal-admin`, `corporate-admin`, `agency-admin` |
| `users.act-on-behalf` | Act on behalf of a user of lower privilege | - | `system-admin`, `internal-admin` |
| `permissions.view` | View the permission catalog and role definitions | - | `system-admin`, `internal-admin`, `corporate-admin`, `agency-admin` |
| `roles.manage-permissions` | Edit the default permissions of a role (system administrators only) | yes | `system-admin` |
| `audit.view` | View the audit trail of the caller's tenant | - | `system-admin`, `internal-admin` |
| `access-matrix.view` | View the role by action access matrix | - | `system-admin` |
