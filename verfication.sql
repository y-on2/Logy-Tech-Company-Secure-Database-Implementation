PROMPT =========================================================================
PROMPT ===( Logy Tech Company Secure Database Implementation verification)======
PROMPT =========================================================================
SET ECHO OFF
SET FEEDBACK ON
SET LINESIZE 200
SET PAGESIZE 100
SET SERVEROUTPUT ON

PROMPT =========================================================================
PROMPT  PHASE 1: INFRASTRUCTURE (Database, Users, Roles) ==>(system)<CDB_SYSTEM>
PROMPT =========================================================================

-- 1. Start in Root to Check PDB Status
ALTER SESSION SET CONTAINER = CDB$ROOT;
SELECT USER FROM DUAL;

PROMPT 1. Check PDB Status
SELECT name, open_mode FROM v$pdbs WHERE name = 'FINALP_PDB';
-- Expected: FINALP_PDB | READ WRITE

-- 2. Switch to Project PDB for the rest of the checks
ALTER SESSION SET CONTAINER = FINALP_PDB;
SHOW CON_NAME;

PROMPT 2. Check All Created Users
SELECT username, account_status, profile, created FROM dba_users 
WHERE username IN ('LOGY_HR', 'LOGY_APP', 'LOGY_SEC_ADMIN', 'USER_MANAGER', 'USER_ANALYST', 'LOGY_AUDIT', 'LOGY_READ_ONLY');
-- Expected: All 7 users listed. Status 'OPEN'.

PROMPT 3. Check All Created Roles
SELECT role, authentication_type, common FROM dba_roles 
WHERE role IN ('ROLE_MANAGER', 'ROLE_ANALYST');

PROMPT =========================================================================
PROMPT  PHASE 2: STORAGE AND DATA ==>(system)<CDB_SYSTEM>
PROMPT =========================================================================

PROMPT 1. Check Standard Tablespace
-- Using UPPER to ensure we match the stored name
SELECT tablespace_name, status, encrypted FROM dba_tablespaces 
WHERE tablespace_name = UPPER('tbs_finalproject_data');
-- Expected: ONLINE | NO (Standard Mode)

PROMPT 2. Check Tables and Row Count
SELECT owner, table_name, tablespace_name, num_rows FROM all_tables 
WHERE owner IN ('LOGY_HR', 'LOGY_APP') ORDER BY owner, table_name;
-- Expected: LOGY_HR.EMPLOYEES, LOGY_APP.CLIENTS

PROMPT 3. Verify Actual Data Access (As Admin)
SELECT * FROM logy_hr.employees;

PROMPT =========================================================================
PROMPT  PHASE 4: PRIVACY POLICIES (VPD & Redaction) ==>(system)
PROMPT =========================================================================

PROMPT 1. Verify VPD Policies (Row Security)
SELECT object_owner, object_name, policy_name, enable 
FROM dba_policies 
WHERE object_owner = 'LOGY_HR';
-- Expected: DEPT_ISOLATION_POLICY | YES

PROMPT 2. Verify Redaction Policies (Column Masking)
SELECT object_owner, object_name, policy_name, expression, enable 
FROM redaction_policies 
WHERE object_owner = 'LOGY_HR';
-- Expected: MASK_NID_ANALYST | ENABLE: YES


PROMPT
PROMPT ==================================================================
PROMPT  PHASE 5 & 9: AUDITING & HARDENING ==>(system)
PROMPT ==================================================================

PROMPT 1. Verify Unified Audit Policies
SELECT policy_name, enabled_option, entity_name, success, failure
FROM audit_unified_enabled_policies 
WHERE policy_name IN ('AUDIT_SENSITIVE_ACCESS', 'AUDIT_LOGIN_FAILURES', 'AUDIT_ADMIN_ACTIONS');
-- Expected: All 3 policies listed.

PROMPT 2. Verify Hardening (Public Revokes)
SELECT table_name, privilege 
FROM dba_tab_privs 
WHERE grantee='PUBLIC' AND table_name IN ('UTL_FILE', 'UTL_SMTP');
-- Expected: No rows selected (Permissions Revoked).

PROMPT 3. Verify FGA (Fine Grained Audit on Salary)
SELECT policy_name, policy_text, policy_column 
FROM dba_audit_policies 
WHERE object_schema = 'LOGY_HR';
-- Expected: AUDIT_HIGH_SALARY_VIEW


PROMPT =========================================================================
PROMPT  PHASE 6: LIFECYCLE MANAGEMENT (Masking & Deletion) ==>(system)
PROMPT =========================================================================

PROMPT 1. Check Secure Deletion Procedure
SELECT owner, object_name, object_type, status FROM all_objects 
WHERE object_name = 'SECURE_DELETE' AND owner = 'LOGY_SEC_ADMIN';
-- Expected: SECURE_DELETE | PROCEDURE | VALID

PROMPT 2. Check Masked Development Table
SELECT first_name, national_id FROM logy_hr.employees_dev;
-- Expected: MASKED_USER | 000-00-0000

PROMPT =========================================================================
PROMPT  PHASE 7: INTEGRITY and  ENCRYPTION (TDE) ==>(system)<CDB_SYSTEM>
PROMPT =========================================================================

PROMPT 1. Check Integrity Trigger
SELECT owner, trigger_name, status FROM dba_triggers 
WHERE trigger_name LIKE 'TRG_EMP_INTEGRITY'; 
-- Expected: TRG_EMP_INTEGRITY | ENABLED

PROMPT 2. Check Data Hash Column
DESC logy_hr.employees;
-- Expected: DATA_HASH column exists

PROMPT 3. Check Encrypted Tablespace
SELECT tablespace_name, encrypted FROM dba_tablespaces
WHERE tablespace_name='TBS_ENCRYPTED_DATA';
-- Expected: ENCRYPTED = YES


PROMPT =========================================================================
PROMPT  PHASE 10: INTRUSION DETECTION (Activity Monitoring) ==>(system)
PROMPT =========================================================================
PROMPT 1. Recent Security Incidents (Last 10 Events)
-- This verifies your detection rules are capturing data
SELECT event_timestamp, dbusername, action_name, return_code, 
       CASE WHEN return_code <> 0 THEN 'ALERT: FAILURE' ELSE 'INFO: SUCCESS' END AS STATUS
FROM unified_audit_trail WHERE object_name = 'EMPLOYEES' OR action_name LIKE '%LOGIN%'
ORDER BY event_timestamp DESC FETCH FIRST 10 ROWS ONLY;
