# Deployment and customer boundaries

AppGuard currently authorizes access by role, team, group, and application. Those scopes control
what a user can do inside one AppGuard deployment. They do not create an organization boundary:
the data model does not attach every record to a customer organization, and administrators are
instance-wide.

Run one isolated AppGuard deployment and database per customer. Do not place unrelated customers
in the same instance or treat teams and groups as tenant isolation. Keep each deployment's database,
secrets, backups, and encryption key separate.

Before offering a shared multi-customer deployment, add an organization identifier and enforce it
in every database query, background job, export, notification, integration, and API authorization
path. Include cross-organization IDOR tests for every resource type and an administrative audit trail
for organization membership and limits. A UI filter or Casbin policy alone is not a tenant boundary.
