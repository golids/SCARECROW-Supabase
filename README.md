# ScareCROW Supabase Backend

This repository contains a backup of the ScareCROW Supabase backend structure and source code.

## What's Included

- Database tables and schema
- Row Level Security (RLS) policies
- PostgreSQL functions and triggers
- Database indexes
- Supabase Edge Functions:
  - `manage-device`
  - `register-client`
- Supabase migration files

## Requirements

- Node.js and npm
- Docker Desktop
- Supabase CLI
- Git

## Update Repository

Open the project in VS Code and run these commands in the terminal.

### 1. Pull the latest database schema

```open docker

```powershell
npx supabase db pull
```

### 2. Download Edge Functions

```powershell
npx supabase functions download manage-device
npx supabase functions download register-client
```

### 3. Review and upload changes to GitHub

```powershell
git status
git add .
git commit -m "Update Supabase backend"
git push origin main
```

## Important Notes

- Run `npx supabase link` first if the local project is not linked to your Supabase project.
- Review changes before committing.
- Never commit environment files, API secrets, service-role keys, or sensitive configuration.
- Database migrations preserve schema changes, not actual table records.
- Do not run `npx supabase db push` as part of this backup workflow.

## Purpose

This repository serves as a version-controlled record of the ScareCROW Supabase database structure, security policies, and backend functions.