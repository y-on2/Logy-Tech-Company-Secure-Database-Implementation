-- =========================================================
-- PROJECT: Logy Tech Company Secure Database Implementation
-- =========================================================
--logy_sec_admin    =>SecAdmin#123
--logy_app          =>AppUser#123
--logy_hr           =>HRData#123
--logy_audit        =>Audit#2025
--logy_read_only    ==>Reader#2025
--user_manager      ==>MgrPass#2025
-- =============================================================================
-- PHASE 1: INFRASTRUCTURE SETUP
-- =============================================================================
-- 1. Switch to Root to Manage PDBs
ALTER SESSION SET CONTAINER = CDB$ROOT;
show con_name;

-- 2. Create the Project PDB (FINAL_PDB)
CREATE PLUGGABLE DATABASE FINALP_PDB 
ADMIN USER pdb_admin IDENTIFIED BY "Admin123!"
FILE_NAME_CONVERT = ('C:\oracle\oradata\ORCL\pdbseed\', 'C:\oracle\oradata\ORCL\FINALP_PDB\');

-- 3. Open and Save State
ALTER PLUGGABLE DATABASE FINALP_PDB OPEN;
ALTER PLUGGABLE DATABASE FINALP_PDB SAVE STATE;

-- 4. Switch Context to FINAL_PDB
ALTER SESSION SET CONTAINER = FINALP_PDB;

-- 5. Create Storage (Standard Mode for Stability)
CREATE TABLESPACE tbs_finalproject_data
DATAFILE 'finalproject_data01.dbf' SIZE 100M AUTOEXTEND ON;

-- 6. Create HR User (Data Owner)
CREATE USER logy_hr IDENTIFIED BY "HRData#123" 
DEFAULT TABLESPACE tbs_finalproject_data QUOTA UNLIMITED ON tbs_finalproject_data;
GRANT CREATE SESSION, CREATE TABLE TO logy_hr;

-- 7. Create App User (Client App)
CREATE USER logy_app IDENTIFIED BY "AppUser#123" 
DEFAULT TABLESPACE tbs_finalproject_data QUOTA UNLIMITED ON tbs_finalproject_data;
GRANT CREATE SESSION, CREATE TABLE TO logy_app;

-- 8. Create Security Admin (The Guardian(ploicy Manager))
CREATE USER logy_sec_admin IDENTIFIED BY "SecAdmin#123";
GRANT CREATE SESSION, CREATE PROCEDURE TO logy_sec_admin;
GRANT EXECUTE ON DBMS_RLS TO logy_sec_admin;
GRANT EXECUTE ON DBMS_REDACT TO logy_sec_admin;

-- 9. Create audit reader(Compliance)
CREATE USER logy_audit IDENTIFIED BY "Audit#2025"
DEFAULT TABLESPACE tbs_finalproject_data QUOTA UNLIMITED ON tbs_finalproject_data;
GRANT CREATE SESSION TO logy_audit;
GRANT SELECT ANY DICTIONARY TO logy_audit; -- Allows viewing audit trails
GRANT AUDIT_VIEWER TO logy_audit;          -- Specific role for auditors
GRANT CREATE VIEW TO logy_audit;

-- 10. Create reader only(Reporting)
CREATE USER logy_read_only IDENTIFIED BY "Reader#2025"
DEFAULT TABLESPACE tbs_finalproject_data;
GRANT CREATE SESSION TO logy_read_only;

show con_name;
-- 11. Create the Dashboard View==>(logy_audit --> Audit#2025)
---verfication as system=>in FINALP_PDB 
SELECT USER FROM DUAL;
---- Switch to PDB
ALTER SESSION SET CONTAINER = FINALP_PDB;

-- Grant DIRECT select permission (Crucial Fix)->system
GRANT SELECT ON UNIFIED_AUDIT_TRAIL TO logy_audit;

--  Verificatoin(system)
SELECT * FROM dba_tab_privs WHERE grantee = 'LOGY_AUDIT' AND table_name = 'UNIFIED_AUDIT_TRAIL';

--create the dashboard as (logy_audit --> Audit#2025)
CREATE OR REPLACE VIEW suspicious_activity_dashboard AS
SELECT 
    event_timestamp,
    dbusername AS user_name,
    action_name,
    object_name,
    return_code,
    sql_text,
    CASE 
        WHEN return_code <> 0 THEN 'CRITICAL: FAILED ATTEMPT'
        WHEN object_name = 'EMPLOYEES' AND action_name = 'SELECT' THEN 'WARNING: SENSITIVE READ'
        WHEN action_name IN ('DROP USER', 'ALTER USER', 'CREATE USER') THEN 'ALERT: ADMIN ACTION'
        ELSE 'INFO'
    END AS alert_level
FROM unified_audit_trail
WHERE 
    return_code <> 0  
    OR object_name = 'EMPLOYEES'
    OR action_name LIKE '%USER%'
ORDER BY event_timestamp DESC;
--verify
SELECT * FROM suspicious_activity_dashboard;


--**********(verfication)(system)
SELECT username, account_status FROM dba_users WHERE username LIKE 'LOGY_%';

SELECT name, open_mode FROM v$pdbs;
-- =============================================================================
-- PHASE 2: DATA SCHEMA and CONTENT
-- =============================================================================
-- 1. Create Employees Table
CREATE TABLE logy_hr.employees (
    emp_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name VARCHAR2(50),
    last_name VARCHAR2(50),
    national_id VARCHAR2(20),
    salary NUMBER(10, 2)
) TABLESPACE tbs_finalproject_data;

-- 2. Create Clients Table
CREATE TABLE logy_app.clients (
    client_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    company_name VARCHAR2(100),
    credit_limit NUMBER(15, 2)
) TABLESPACE tbs_finalproject_data;

CREATE TABLE logy_hr.departments (
    dept_id NUMBER PRIMARY KEY,
    dept_name VARCHAR2(50)
) TABLESPACE tbs_finalproject_data;

CREATE TABLE logy_app.projects (
    proj_id NUMBER PRIMARY KEY,
    proj_name VARCHAR2(100),
    budget NUMBER
) TABLESPACE tbs_finalproject_data;

-- 3. Insert Initial Data
INSERT INTO logy_hr.employees (first_name, last_name, national_id, salary) 
VALUES ('Ezz', 'Aldeen', '111-22-3333', 300000);

INSERT INTO logy_app.clients (company_name, credit_limit) 
VALUES ('TechCorp', 1000000);

INSERT INTO logy_app.clients (company_name, credit_limit) 
VALUES ('Techali', 2000000);

INSERT INTO logy_app.clients (company_name, credit_limit) 
VALUES ('Techkhalid', 2000000);

-- 4. Update Schema for Security Policies
ALTER TABLE logy_hr.employees ADD department_id NUMBER;
UPDATE logy_hr.employees SET department_id = 10 WHERE first_name = 'Ezz';
COMMIT;

--**************(verify)
SELECT owner, table_name, tablespace_name FROM dba_tables 
WHERE owner = 'LOGY_HR';

--(data content)
SELECT * FROM logy_hr.employees;
SELECT * FROM logy_app.clients;

-- =============================================================================
-- PHASE 3: AUTHENTICATION and ACCESS CONTROL (RBAC)
-- =============================================================================
--check-->system-->(FINALP_PDB)if not switch it
SELECT USER FROM DUAL;
SELECT SYS_CONTEXT('USERENV', 'CON_NAME') FROM DUAL;
ALTER SESSION SET CONTAINER = FINALP_PDB;

-- 1. Create the Function (Logic for "Complex" Password)
ALTER SESSION SET CONTAINER = FINALP_PDB;

-- 2. Create the Password Complexity Function (As Admin)
CREATE OR REPLACE FUNCTION logy_complexity_check (
    username IN VARCHAR2,
    password IN VARCHAR2,
    old_password IN VARCHAR2
) RETURN BOOLEAN IS
BEGIN
    -- Rule: Must be at least 8 characters
    IF LENGTH(password) < 8 THEN
        RAISE_APPLICATION_ERROR(-20001, 'Password length less than 8 characters');
    END IF;

    -- Rule: Must contain at least one number
    IF NOT REGEXP_LIKE(password, '[0-9]') THEN
        RAISE_APPLICATION_ERROR(-20003, 'Password must contain at least one number');
    END IF;

    RETURN TRUE;
END;
/
--*******************************(verfication)
--verify as weak password 
ALTER USER user_manager IDENTIFIED BY "weak";

-- Try a STRONG password (Should SUCCEED)
ALTER USER user_manager IDENTIFIED BY "MgrPass#2025";

--===================================
-- 1. Create Secure Password Profile
CREATE PROFILE prof_logy_sec LIMIT
    PASSWORD_LIFE_TIME 90
    FAILED_LOGIN_ATTEMPTS 3
    PASSWORD_LOCK_TIME 1;

-- 2. Create Roles
CREATE ROLE role_manager;
CREATE ROLE role_analyst;

-- 3. Create Users with Profiles & Roles
CREATE USER user_manager IDENTIFIED BY "MgrPass#2025" PROFILE prof_logy_sec;
GRANT role_manager TO user_manager;
GRANT CREATE SESSION TO user_manager;

CREATE USER user_analyst IDENTIFIED BY "AnaPass#2025" PROFILE prof_logy_sec;
GRANT role_analyst TO user_analyst;
GRANT CREATE SESSION TO user_analyst;

-- 4. Grant Object Privileges
-- Manager gets Select/Update on HR
GRANT SELECT, UPDATE ON logy_hr.employees TO role_manager;
-- Analyst gets Select on App Clients
GRANT SELECT ON logy_app.clients TO role_analyst;
-- Security Admin gets Power to Delete/Manage for maintenance
GRANT SELECT, UPDATE, DELETE ON logy_hr.employees TO logy_sec_admin;
--5. Restricted View
CREATE VIEW logy_hr.public_emp_view AS
SELECT emp_id, first_name, last_name, department_id 
FROM logy_hr.employees;


//user_manager,  user_analyst,   logy_sec_admin
SET ROLE role_manager; -- Activate
SET ROLE NONE; -- Deactivate
SELECT * FROM session_roles;

--(testing superation of Duties)=> connecting as any of users
SELECT text FROM all_source WHERE name = 'AUTH_DEPT' AND owner = 'LOGY_SEC_ADMIN';

-- =============================================================================
-- PHASE 4: PRIVACY POLICIES =>VPD, ,REDACTION, hashing , Tokenization)
-- =============================================================================
--=================================(VPD)
-- 1. Create VPD Policy Function=>(logy_sec_admin / SecAdmin#123)
CREATE OR REPLACE FUNCTION logy_sec_admin.auth_dept(
 schema_p IN VARCHAR2,
 table_p IN VARCHAR2
)
RETURN VARCHAR2
IS
 v_user VARCHAR2(100);
 v_hour NUMBER;
BEGIN
 v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');
 v_hour := TO_NUMBER(TO_CHAR(SYSDATE, 'HH24'));

 -- 1. Global Rule: No access before 8 AM or after 6 PM(8, 18)=>1-5
-- IF v_hour < 8 OR v_hour > 10 THEN
--    RETURN '1=2'; --(return false<no one >)
-- END IF;

 -- 2. Context Rule: Manager Isolation
 IF v_user = 'USER_MANAGER' THEN
   RETURN 'DEPARTMENT_ID = 10';
 ELSE
   RETURN '1=1'; 
 END IF;
END;
/

-- 2. Apply VPD Policy
BEGIN
 DBMS_RLS.ADD_POLICY (
  object_schema => 'LOGY_HR',
  object_name => 'EMPLOYEES',
  policy_name => 'dept_isolation_policy',
  function_schema => 'LOGY_SEC_ADMIN',
  policy_function => 'auth_dept',
  statement_types => 'SELECT'
 );
END;
/
--=================================(redaction)
-- 3. Apply Redaction (Mask National ID for Analysts)
BEGIN
 DBMS_REDACT.ADD_POLICY(
   object_schema => 'LOGY_HR',
   object_name   => 'EMPLOYEES',
   column_name   => 'NATIONAL_ID',
   policy_name   => 'mask_nid_analyst',
   function_type => DBMS_REDACT.FULL,
   expression    => 'SYS_CONTEXT(''USERENV'',''SESSION_USER'') = ''USER_ANALYST'''
 );
END;
/
--=================================(Hashing)=>system
CREATE TABLE logy_hr.secure_contacts (
    contact_id NUMBER,
    email_hash VARCHAR2(64) -- Stores SHA256 hash
) TABLESPACE tbs_finalproject_data;

INSERT INTO logy_hr.secure_contacts VALUES (1, STANDARD_HASH('ali.aldeen@logy.com', 'SHA256'));
--=================================(Tokenization)
CREATE TABLE logy_hr.token_map (
    real_credit_card VARCHAR2(16),
    token_value      VARCHAR2(16)
) TABLESPACE tbs_finalproject_data;

-- Create Tokenization Function (Simulates a Token Server)
CREATE OR REPLACE FUNCTION logy_app.get_token(p_real_cc VARCHAR2) 
RETURN VARCHAR2 IS
  v_token VARCHAR2(16);
BEGIN
  -- Generate a random 16-digit token
  v_token := TRUNC(DBMS_RANDOM.VALUE(1000000000000000, 9999999999999999));
  
  -- Store the mapping (Real Data <-> Token)
  INSERT INTO logy_hr.token_map (real_credit_card, token_value)
  VALUES (p_real_cc, v_token);
  
  RETURN v_token;
END;
/
GRANT INSERT, SELECT ON logy_hr.token_map TO logy_app;

-- Test Tokenization
-- Imagine storing only the TOKEN in your app, while the MAP is safe in HR
DECLARE
  v_masked_cc VARCHAR2(16);
BEGIN
  v_masked_cc := logy_app.get_token('4111-2222-3333-4444');
  DBMS_OUTPUT.PUT_LINE('Original CC is hidden. App uses Token: ' || v_masked_cc);
END;
/
--(Expand the column)
ALTER TABLE logy_hr.token_map MODIFY real_credit_card VARCHAR2(20);





-- =============================================================================
-- PHASE 5: AUDITING and HARDENING
-- =============================================================================
-- 1. Clean up old policies (if any)==>CDB_SYSDBA_d
BEGIN
  EXECUTE IMMEDIATE 'DROP AUDIT POLICY audit_login_failures';
EXCEPTION
  WHEN OTHERS THEN NULL;
END;
/

-- 2. Create Audit Policies
CREATE AUDIT POLICY audit_login_failures ACTIONS LOGON;
CREATE AUDIT POLICY audit_sensitive_access ACTIONS SELECT ON logy_hr.employees;
CREATE AUDIT POLICY audit_admin_actions ACTIONS CREATE USER, DROP USER;
AUDIT POLICY audit_admin_actions;
--FGA Policy (Fine Grained Auditing on Salary)
BEGIN
  DBMS_FGA.ADD_POLICY(
    object_schema   => 'LOGY_HR',
    object_name     => 'EMPLOYEES',
    policy_name     => 'audit_high_salary_view',
    audit_condition => 'SALARY > 20000', 
    audit_column    => 'SALARY'
  );
END;
/
-- 3. Enable Policies
AUDIT POLICY audit_sensitive_access;
AUDIT POLICY audit_login_failures WHENEVER NOT SUCCESSFUL;
ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME 60; -- 3: Harden default profile
REVOKE EXECUTE ON UTL_SMTP FROM PUBLIC;            -- 4: Revoke mailer
-- ALTER SYSTEM SET AUDIT_TRAIL=DB SCOPE=SPFILE;   -- Note: Must be run in CDB$ROOT, skipped for PDB script.

--*******************************(verfication)==>sys
---(partical check)
ALTER SESSION SET CONTAINER = FINALP_PDB;
SET SERVEROUTPUT ON;

-- Run the Secure Delete Procedure
EXEC logy_sec_admin.secure_delete(p_id => 1); 
----(required logs)
SELECT event_timestamp, dbusername, action_name, object_name, return_code,
       CASE WHEN return_code <> 0 THEN 'FAILURE' ELSE 'SUCCESS' END AS STATUS
FROM unified_audit_trail
WHERE event_timestamp > SYSDATE - 1 -- Last 24 hours
ORDER BY event_timestamp DESC;

--------------------------------------------------------------------------------
--(Activity Monitoring and Intrusion Detection<sys>3times)======>user_manager-->wrongpassword
SELECT dbusername, 
       count(*) as failed_attempts, 
       max(event_timestamp) as last_attempt_time
FROM unified_audit_trail
WHERE return_code <> 0 
AND event_timestamp > SYSDATE - 1/24
GROUP BY dbusername
HAVING count(*) >= 3;
--------------------------------------------------------------------------------
--(Detection Rule 2: Suspicious After-Hours Access)===>(logy_hr) out of time
SELECT * FROM logy_hr.employees;
-- DETECT: Access Outside Business Hours (6 PM - 8 AM)
SELECT 
    event_timestamp,
    dbusername AS "User", 
    action_name AS "Action", 
    object_name AS "Target Table",
    to_char(event_timestamp, 'HH24:MI:SS') AS "Access Time",
    'WARNING: After-Hours Access' AS "Alert"
FROM unified_audit_trail
WHERE object_schema = 'LOGY_HR'
  AND object_name = 'EMPLOYEES'
  AND (
       TO_NUMBER(TO_CHAR(event_timestamp, 'HH24')) >= 18 -- After 18:00 (6 PM)
       OR 
       TO_NUMBER(TO_CHAR(event_timestamp, 'HH24')) < 8   -- Before 08:00 (8 AM)
      )
ORDER BY event_timestamp DESC;


---==========================
-- 4. Hardening==>((Revocation and Account Locking))-->Transparent Data Encryption-->RMAN Encryption
--===========================
-- Users with Powerful Roles (DBA)
SELECT grantee, granted_role FROM dba_role_privs 
WHERE granted_role IN ('DBA', 'PDB_DBA') AND grantee NOT IN ('SYS', 'SYSTEM');

-- Dangerous Public grants
SELECT table_name, privilege FROM dba_tab_privs 
WHERE grantee = 'PUBLIC' AND table_name IN ('UTL_SMTP', 'UTL_FILE', 'UTL_HTTP');

-- Default Accounts Status
SELECT username, account_status FROM dba_users 
WHERE username IN ('SCOTT', 'HR', 'SH', 'OE', 'MDDATA', 'SPATIAL_WFS_ADMIN_USR');

-- Password Profile Completeness(unlimited<bad>, limited<secure>)
SELECT profile, resource_name, limit FROM dba_profiles 
WHERE resource_name = 'PASSWORD_LIFE_TIME';

--Network Encryption ( active connection)
SELECT DISTINCT network_service_banner FROM v$session_connect_info 
WHERE network_service_banner LIKE '%Encryption service adapter%';
-----------
--1(revoke)=>solution
REVOKE EXECUTE ON UTL_SMTP FROM PUBLIC;
REVOKE EXECUTE ON UTL_FILE FROM PUBLIC;

--2.Secure the default environment
ALTER USER scott ACCOUNT LOCK;

-- 3.Toughen the default profile password lifecycle
ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME 60;

--*******************************(verfication)==>sys
SELECT username, account_status FROM dba_users WHERE username = 'SCOTT';        --account Lock
SELECT tablespace_name, encrypted FROM dba_tablespaces WHERE encrypted = 'YES'; --Encryption Status


SELECT username, account_status FROM dba_users 
WHERE username IN ('SCOTT', 'HR', 'SH', 'BI', 'OE', 'PM', 'IX');



-- =============================================================================
-- PHASE 6: LIFECYCLE MANAGEMENT (MASKING and DELETION)
-- =============================================================================
-- 1. Create Masked Development Table
BEGIN
  EXECUTE IMMEDIATE 'DROP TABLE logy_hr.employees_dev PURGE';
EXCEPTION
  WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE logy_hr.employees_dev AS SELECT * FROM logy_hr.employees;

UPDATE logy_hr.employees_dev
SET first_name = 'MASKED_USER',
    national_id = '000-00-0000';
COMMIT;

-- 2. Create Secure Deletion Procedure (Digital Shredding)
CREATE OR REPLACE PROCEDURE logy_sec_admin.secure_delete(p_id NUMBER) IS
BEGIN
    -- Overwrite data first
    UPDATE logy_hr.employees 
    SET first_name='X', national_id='X', salary=0 
    WHERE emp_id = p_id;
    
    -- Then delete
    DELETE FROM logy_hr.employees WHERE emp_id = p_id;
    
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('User ' || p_id || ' has been securely deleted.');
END;
/
--***(apply)
SELECT first_name, national_id FROM logy_hr.employees_dev;

-----------------------
--Verification(cmd)
-----------------------
--A. Test VPD (Manager Isolation)==>2out of time, if 1 in worktime(8am-6pm)
--sqlplus user_manager/MgrPass#2025@FINALP_PDB
SELECT count(*) AS "Rows_Visible" FROM logy_hr.employees;

--B. Test Redaction (Analyst Masking)
--sqlplus user_analyst/AnaPass#2025@FINAL_PDB
SELECT first_name, national_id FROM logy_hr.employees;

SET LINESIZE 120
SELECT first_name, national_id FROM logy_hr.employees_dev;


-- =============================================================================
-- PHASE 7: Data---->(Integrity , encryption, Backup and Recovery)
-- =============================================================================
--=================================(Integrity)
--============================================
--verify who am i 
SELECT USER, SYS_CONTEXT('USERENV', 'SESSION_USER') AS SESSION_USER FROM dual;

-- Switch to your PDB
ALTER SESSION SET CONTAINER = FINALP_PDB;

-- Grant permissions
GRANT CREATE ANY TRIGGER TO logy_sec_admin;
GRANT EXECUTE ON DBMS_CRYPTO TO logy_sec_admin;
GRANT SELECT, INSERT, UPDATE ON logy_hr.employees TO logy_sec_admin;

-- Add Hash Column (Run as logy_hr)==>logy_hr==>HRData#123
ALTER TABLE employees ADD (data_hash VARCHAR2(100));

--Create Integrity Trigger (Run as logy_sec_admin)-->logy_sec_admin --> SecAdmin#123
CREATE OR REPLACE TRIGGER trg_emp_integrity
BEFORE INSERT OR UPDATE ON logy_hr.employees
FOR EACH ROW
BEGIN
  SELECT STANDARD_HASH(:NEW.emp_id || :NEW.first_name || :NEW.salary, 'SHA1')
  INTO :NEW.data_hash
  FROM DUAL;
END;
/


--====(auto hashing(LOGY_SEC_ADMIN))
SELECT USER, SYS_CONTEXT('USERENV', 'SESSION_USER') AS SESSION_USER FROM dual;
-- 1. Create the Integrity Trigger
CREATE OR REPLACE TRIGGER logy_sec_admin.trg_emp_integrity
BEFORE INSERT OR UPDATE ON logy_hr.employees
FOR EACH ROW
DECLARE
    v_input_string VARCHAR2(4000);
BEGIN
    -- 1. Combine the data
    v_input_string := :NEW.emp_id || :NEW.first_name || :NEW.salary;
    
    -- 2. Hash it using the Package
    :NEW.data_hash := DBMS_CRYPTO.HASH(
        src => UTL_I18N.STRING_TO_RAW(v_input_string, 'AL32UTF8'),
        typ => DBMS_CRYPTO.HASH_SH1
    );
END;
/

-----------------------
--Verification(logy_hr)
-----------------------
--a.Insert a test user
INSERT INTO employees (first_name, last_name, national_id, salary, department_id)
VALUES ('Tamper', 'Test', '999-99-9999', 50000, 10);
COMMIT;

-- b. Check the hash
SELECT first_name, salary, data_hash FROM employees WHERE first_name = 'Tamper';

--c out of time (CDB_SYSDBA_d)
SELECT first_name, salary, data_hash 
FROM logy_hr.employees 
WHERE first_name = 'Tamper';
--=================================(encryption)====
--=================================================
--(note)=>Due to Lab Wallet constraints, we used Standard Storage. 
--------------------------------------------------------------------------------
--First:Checking status
SELECT name, open_mode FROM v$pdbs;

--Second:creating the wallet and master key and open it for all pdb(CDB$root)
alter session set container = CDB$ROOT;
show con_name;
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE 'C:\oracle\tde\wallet' IDENTIFIED BY 
"passTest#20200"; 

ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "passTest#20200" WITH BACKUP;

ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "passTest#20200" 
CONTAINER=ALL;
---(verify)
SELECT W.STATUS, W.WALLET_TYPE, K.KEY_ID  
FROM V$ENCRYPTION_WALLET W  
LEFT JOIN V$ENCRYPTION_KEYS K ON W.CON_ID = K.CON_ID;

-- Third:in PDB=> connect, create another master key if you are schema owner
ALTER SESSION SET CONTAINER = FINALP_PDB;

ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "passTest#20200" 
WITH BACKUP CONTAINER=CURRENT;

-- STEP B:Create the Encrypted Tablespace
CREATE TABLESPACE tbs_encrypted_data 
DATAFILE 'C:\oracle\oradata\ORCL\FINALP_PDB\enc_data02.dbf' SIZE 100M AUTOEXTEND ON
ENCRYPTION USING 'AES256' DEFAULT STORAGE(ENCRYPT);

--*****(VERIFICATION)
SELECT tablespace_name, encrypted FROM dba_tablespaces 
WHERE tablespace_name = 'TBS_ENCRYPTED_DATA';

SELECT W.STATUS, W.WALLET_TYPE, K.KEY_ID  
FROM V$ENCRYPTION_WALLET W  
LEFT JOIN V$ENCRYPTION_KEYS K ON W.CON_ID = K.CON_ID;

--create your test table
CREATE TABLE logy_hr.test_enc_table (
    id NUMBER, 
    data VARCHAR2(50)
) TABLESPACE tbs_encrypted_data;



--=================================(Backup)====
--=============================================
set ORACLE_SID=ORCL
--Step 1: Open all PDBs and make diratctory to file 
mkdir C:\oracle\logs

-- Step 2: Configure Encrypted Backup and save it into the path
set ORACLE_SID=ORCL
rman target sys/makeit12%@localhost:1521/orcl LOG=C:\oracle\logs\project_backup.log
CONFIGURE ENCRYPTION FOR DATABASE ON;
SET ENCRYPTION ON IDENTIFIED BY "BackupPass123" ONLY;

-- Step 3: Catalog Datafile Copy
CATALOG DATAFILECOPY 'J:\UST\Information storage security\Practical(Thana)\labs\Project\USERS01.DBF';
SWITCH DATAFILE 7 TO COPY;

-- Step 4: Perform Full Backup
BACKUP DATABASE PLUS ARCHIVELOG TAG 'SECURE_PROJECT_BKP';

-- Step 5: Verify Backup
RESTORE DATABASE VALIDATE;
LIST BACKUP TAG 'SECURE_PROJECT_BKP';
EXIT;

--(veify Identify Datafile 17)
sqlplus sys/makeit12% as sysdba
SELECT file#, name, status, enabled FROM v$datafile WHERE file#=17;

--*******************(physical check)
dbv file=C:\ORACLE\ORADATA\ORCL\SYSTEM01.DBF userid=sys/makeit12%

---****(verify encrypted file)
dbv file=C:\oracle\oradata\ORCL\FINALP_PDB\enc_data02.dbf userid=sys/makeit12%

--(if fail is owing to BACKUP(ORA-00258 and RMAN-06149)--->crash simulation
--RESTORE DATABASE VALIDATE fails because no backup was created
--Option 1: Switch to ARCHIVELOG Mode
SHUTDOWN IMMEDIATE;
STARTUP MOUNT;
ALTER DATABASE ARCHIVELOG;
ALTER DATABASE OPEN;

--Option 2: Use Simple Backup
BACKUP DATABASE TAG 'SECURE_PROJECT_BKP';


--=================================(Recovery)===
--==============================================
--sql
SHUTDOWN ABORT;
STARTUP MOUNT;
RESTORE DATABASE VALIDATE;
LIST BACKUP;

--cmd
RMAN> RESTORE DATABASE VALIDATE;
RMAN> LIST BACKUP;


