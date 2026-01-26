# Logy Tech Secure Database Implementation
**Academic Capstone Project | Bachelor in Cyber Security**

## Executive Summary
This project implements a defense-in-depth security architecture for Oracle Database 19c/21c. It enforces Separation of Duties (SoD), granular access control, and cryptographic protections to secure PII and financial data against internal and external threats.

## System Architecture
The system operates within a dedicated Pluggable Database (`FINALP_PDB`) utilizing five distinct schemas to prevent privilege escalation:

* **LOGY_HR:** Data owner for sensitive personnel and payroll records.
* **LOGY_APP:** Manages transactional data for clients and projects.
* **LOGY_SEC_ADMIN:** Manages security policies (VPD, Redaction) without access to business data.
* **LOGY_AUDIT:** Dedicated auditor account with access restricted to the Unified Audit Trail.
* **LOGY_READ_ONLY:** Restricted account for reporting purposes.

## Implemented Security Controls

### Authentication and Authorization (RBAC)
* **Profile Hardening:** The `PROF_LOGY_SEC` profile enforces strong password complexity, a 90-day lifecycle, and account lockouts after three failed attempts.
* **Role Segregation:** Distinct roles (`ROLE_MANAGER`, `ROLE_ANALYST`) ensure users operate under the Principle of Least Privilege.

### Granular Access Control
* **Virtual Private Database (VPD):** Row-level security policies restrict users to their specific department's data and enforce business-hour access rules (08:00–18:00).
* **Dynamic Redaction:** The `DBMS_REDACT` package masks `NATIONAL_ID` columns in real-time for analysts.

### Cryptography and Integrity
* **Transparent Data Encryption (TDE):** Data-at-rest is protected using AES-256 encryption within the `TBS_ENCRYPTED_DATA` tablespace.
* **Tokenization:** Credit card numbers are replaced with random tokens via a custom function, segregating the mapping table in a secure schema.
* **Integrity Hashing:** A trigger generates SHA-1 hashes of critical rows upon insertion to detect unauthorized tampering.

### Auditing and Monitoring
* **Suspicious Activity Dashboard:** A custom view aggregates critical alerts including failed logins and unauthorized administrative actions.
* **Fine-Grained Auditing (FGA):** Specifically monitors access to high-value transactions, such as salary modifications exceeding thresholds.

## Repository Structure
* **docs/**: Contains the full academic report and architectural diagrams.
* **scripts/logy.sql**: The primary deployment script covering infrastructure setup, schema creation, and policy application.
* **scripts/verification.sql**: A post-deployment validation suite to confirm PDB status, policy enforcement, and encryption states.

## Deployment and Verification

### 1. Installation
Execute the main script as a user with `SYSDBA` privileges to initialize the PDB and apply security configurations(logy.sql)

### 2. Verfication
SQL> @scripts/verification.sql

## Implemented by
* **Jalal Ameen**
* **Ezz Aldeen Alshalafi**

## Supervised by
* **Thana Al Ashwal**
