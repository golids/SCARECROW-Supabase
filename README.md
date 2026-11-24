# ScareCROW Supabase Backend

This repository contains the database schema, PostgreSQL migrations, and Supabase Edge Functions used by the **ScareCROW Smart Scarecrow System**.

ScareCROW is a solar-powered bird detection and crop protection system designed to help protect rice fields through automated bird detection and deterrence.

## Project Information

| Item | Description |
|---|---|
| Project Name | ScareCROW |
| Backend Platform | Supabase |
| Database | PostgreSQL |
| Serverless Functions | Supabase Edge Functions |
| Version Control | Git and GitHub |
| Repository | Private |

## Repository Structure

```text
scarecrow-supabase/
│
├── .gitignore
├── README.md
│
└── supabase/
    ├── .gitignore
    │
    ├── migrations/
    │   └── 20261124172949_remote_schema.sql
    │
    └── functions/
        ├── manage-device/
        │   └── index.ts
        │
        └── register-client/
            └── index.ts
```

## Database Overview

The database currently includes the following tables:

| Table | Purpose |
|---|---|
| `admin_users` | Stores administrator account references |
| `detection_logs` | Stores bird detection and device event records |
| `device_assignments` | Manages device assignments to farmers |
| `device_audit_logs` | Records device status changes and audit events |
| `devices` | Stores registered ScareCROW device information |
| `maintenance_notes` | Stores device maintenance records |
| `notification_preferences` | Stores notification settings |
| `profiles` | Stores user profile information |

### Database Security

The database schema includes:

- Row Level Security (RLS) enabled on all eight tables.
- Policies controlling access to database records.
- PostgreSQL functions for administrative and device-related operations.
- Triggers for device status logging and profile updates.
- Database indexes for query performance.

The initial schema migration is stored in:

`supabase/migrations/20261124172949_remote_schema.sql`

## Supabase Edge Functions

### 1. manage-device

Location: `supabase/functions/manage-device/index.ts`

Handles administrative device management operations.

### 2. register-client

Location: `supabase/functions/register-client/index.ts`

Handles farmer/client registration operations.

Both functions are deployed separately to Supabase and their source code is maintained in this repository.

## Requirements

- Node.js and npm
- Docker Desktop
- WSL 2 (Windows users)
- Supabase CLI
- Git
- Access to the ScareCROW Supabase project

## Local Setup

### 1. Clone the repository

```bash
git clone <YOUR_PRIVATE_GITHUB_REPOSITORY_URL>
cd scarecrow-supabase
```

### 2. Install or run the Supabase CLI

The Supabase CLI can be executed through `npx`:

```bash
npx supabase --version
```

### 3. Link the Supabase project

```bash
npx supabase link --project-ref <YOUR_PROJECT_REF>
```

You will need the appropriate Supabase account access and database password when prompted.

### 4. Start local Supabase services (optional)

Make sure Docker Desktop is running.

```bash
npx supabase start
```

This starts a local Supabase development environment. It does not replace or modify the production project.

## Database Migration Management

The existing production schema was captured using:

```bash
npx supabase db pull --remote
```

The resulting migration file represents the database schema at the time it was pulled.

**Important:** Review all migration SQL carefully before applying changes to the production database.

Do not execute `db push`, `db reset`, or other database-changing commands against production without reviewing the migration and confirming the intended changes.

## Deploying Edge Functions

Edge Functions are deployed separately from database migrations.

To deploy the device management function:

```bash
npx supabase functions deploy manage-device
```

To deploy the client registration function:

```bash
npx supabase functions deploy register-client
```

Deployment requires appropriate project permissions and correctly configured environment variables and secrets.

Do not deploy functions to production without reviewing the source code and testing the changes.

## Security Guidelines

- Never commit `.env` files or credentials.
- Never expose the Supabase Service Role Key.
- Never commit database passwords, API secrets, or private keys.
- Keep sensitive configuration files outside version control.
- Use Supabase environment secrets for deployed Edge Functions.
- Maintain appropriate Row Level Security policies.
- Review source code before committing or deploying changes.

The following files and directories are excluded from version control:

- `.env` files
- `supabase/config.jsonc` (contains locally configured sensitive values)
- `supabase/.temp/`
- Local dependency and temporary files

## Backup and Data Preservation

This repository preserves the database schema and selected backend source code.

**It is not a complete database backup.**

The migration files do not contain historical database records, including:

- Bird detection history
- Device activity records
- Farmer account records
- Maintenance records

Actual database records require a separate backup strategy, such as scheduled PostgreSQL backups or secure database exports.

Supabase Auth users, Storage objects, project secrets, and dashboard settings also require separate backup or documentation procedures.

## Version Control

This repository uses Git to track backend changes.

Example commands:

```bash
git status
git add .
git commit -m "Describe your changes"
git push origin main
```

Always inspect staged files before committing to ensure that credentials and sensitive information are not included.

## Project Maintenance

This repository is intended to serve as the version-controlled backend source for the ScareCROW system.

Future updates should preserve database integrity, access permissions, Edge Function functionality, and historical detection records.

---

**ScareCROW Project**  
Smart Bird Detection and Crop Protection System  
Backend Repository – Supabase