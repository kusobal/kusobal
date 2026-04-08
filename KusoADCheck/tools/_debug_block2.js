
// Get Group Membership data from PowerShell
var GroupMembers = null;
var ObjectRiskDetails = null;
var PingRuleDetailsMap = {"Privileged Infrastructure||Tier1: GPO write permission abuse":{"c":"Privileged Infrastructure","r":"Tier1: GPO write permission abuse","s":"Low","n":0,"m":"No risky GPO write delegation detected","p":"Remove unsafe GPO edit and modify-security rights from non-admin principals.","f":"MITRE ATT\u0026CK: T1484.001","d":[],"a":"Non-privileged identities can edit or modify GPO security","o":"Get-GPPermission delegated rights","u":"Remove unsafe GPO edit/modify-security delegations and enforce least privilege delegation model."},"Privileged Infrastructure||Privileged Review: Group Policy Creator Owners":{"c":"Privileged Infrastructure","r":"Privileged Review: Group Policy Creator Owners","s":"Medium","n":4,"m":"Users=4, Computers=0, Indirect=0, Unresolved=0","p":"GPO creator rights should align with delegated administration boundaries.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Group Policy Creator Owners: User members: 4 [Medium]","Group Policy Creator Owners: User members: 4 [Medium]"]},"Privileged Infrastructure||Tier2: CredSSP exposure":{"c":"Privileged Infrastructure","r":"Tier2: CredSSP exposure","s":"Low","n":0,"m":"No CredSSP enabled DC detected","p":"Disable CredSSP where not required and prefer Kerberos constrained delegation patterns.","f":"Tier-2 AD Baseline Control / MITRE ATT\u0026CK mapping required","d":[],"a":"CredSSP on DCs increases credential relay/exposure scenarios","o":"WSMan CredSSP service auth setting","u":"Disable CredSSP where not strictly required."},"Privileged Accounts||adminCount drift":{"c":"Privileged Accounts","r":"adminCount drift","s":"Medium","n":1,"m":"krbtgt","p":"Review adminCount=1 accounts outside privileged groups and fix ACL inheritance where applicable.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["krbtgt: adminCount=1 but not in DA/EA/SA baseline list [Medium]"],"a":"Protected ACL residue / privilege drift","o":"adminCount=1 compared to privileged baseline","u":"Review and remediate accounts with privilege drift in adminCount=1 list."},"Stale Objects||Machine account quota":{"c":"Stale Objects","r":"Machine account quota","s":"Low","n":"N/A","m":"Machine account quota unavailable","p":"Set machine account quota to 0 when possible and use controlled join workflows.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Non-admins can create machine accounts","o":"ms-DS-MachineAccountQuota","u":"Set machine account quota to 0 unless a controlled join process requires otherwise."},"Privileged Infrastructure||Tier0: Dangerous ACE on critical objects":{"c":"Privileged Infrastructure","r":"Tier0: Dangerous ACE on critical objects","s":"Critical","n":28,"m":"NT AUTHORITY\\SYSTEM on DC=kuso,DC=local [GenericAll]; BUILTIN\\Administrators on DC=kuso,DC=local [WriteDacl,WriteOwner]; KUSO\\Domain Admins on DC=kuso,DC=local [WriteDacl,WriteOwner]; KUSO\\Enterprise Admins on DC=kuso,DC=local [GenericAll]; KUSO\\Organization Management on DC=kuso,DC=local [GenericAll]","p":"Remove non-essential GenericAll/GenericWrite/WriteDacl/WriteOwner ACEs from Tier-0 objects.","f":"Tier-0 AD Security Control / MITRE ATT\u0026CK technique mapping required","d":["NT AUTHORITY\\SYSTEM: Object=DC=kuso,DC=local, Rights=GenericAll [Critical]","BUILTIN\\Administrators: Object=DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]","KUSO\\Domain Admins: Object=DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]","KUSO\\Enterprise Admins: Object=DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Organization Management: Object=DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Windows Permissions: Object=DC=kuso,DC=local, Rights=WriteDacl [Critical]","KUSO\\Exchange Windows Permissions: Object=DC=kuso,DC=local, Rights=WriteDacl [Critical]","NT AUTHORITY\\SYSTEM: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","BUILTIN\\Administrators: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]","KUSO\\Domain Admins: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]","KUSO\\Enterprise Admins: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]","KUSO\\Organization Management: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=CN=AdminSDHolder,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","NT AUTHORITY\\SYSTEM: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Domain Admins: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]","KUSO\\Organization Management: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Windows Permissions: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=WriteDacl [Critical]","KUSO\\Exchange Windows Permissions: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=WriteDacl [Critical]","KUSO\\Exchange Trusted Subsystem: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Exchange Trusted Subsystem: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","KUSO\\Enterprise Admins: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=GenericAll [Critical]","BUILTIN\\Administrators: Object=CN=Policies,CN=System,DC=kuso,DC=local, Rights=WriteDacl,WriteOwner [Critical]"],"a":"Critical AD objects grant risky write rights to non-approved principals","o":"ACL review of Tier-0 directory objects","u":"Remove GenericAll/GenericWrite/WriteDacl/WriteOwner from non-essential principals."},"Privileged Infrastructure||Tier1: Pre-Windows 2000 compatible access":{"c":"Privileged Infrastructure","r":"Tier1: Pre-Windows 2000 compatible access","s":"High","n":1,"m":"Authenticated Users","p":"Remove broad identities from Pre-Windows 2000 Compatible Access group.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Legacy compatibility group contains broad principals","o":"Pre-Windows 2000 Compatible Access group membership","u":"Remove broad identities and keep legacy access disabled."},"Privileged Infrastructure||Privileged Review: Account Operators":{"c":"Privileged Infrastructure","r":"Privileged Review: Account Operators","s":"High","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Accounts with broad account-management rights should remain empty in modern tiered administration.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: Enterprise Key Admins":{"c":"Privileged Infrastructure","r":"Privileged Review: Enterprise Key Admins","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Key administration rights can affect account credentials and key material.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Tier0: Kerberoastable normal users":{"c":"Privileged Infrastructure","r":"Tier0: Kerberoastable normal users","s":"Low","n":0,"m":"No non-privileged SPN user found","p":"Migrate service identities to gMSA, rotate stale passwords, and remove unnecessary SPNs.","f":"Tier-0 AD Security Control / MITRE ATT\u0026CK technique mapping required","d":[],"a":"Non-privileged user accounts expose SPN/TGS cracking paths","o":"User objects with servicePrincipalName","u":"Move SPNs to gMSA/service identities and harden passwords."},"Anomalies||GPP cpassword remnants":{"c":"Anomalies","r":"GPP cpassword remnants","s":"Low","n":0,"m":"No cpassword pattern in SYSVOL XML","p":"Remove GPP password entries and rotate any potentially exposed credentials immediately.","f":"CVE-2014-1812 / MITRE ATT\u0026CK: T1552.006","d":[],"a":"Credential residue risk inside SYSVOL","o":"SYSVOL Policies XML search for cpassword","u":"Remove GPP password entries and rotate affected credentials."},"Privileged Infrastructure||Tier1: Privileged 24h behavior anomalies":{"c":"Privileged Infrastructure","r":"Tier1: Privileged 24h behavior anomalies","s":"Low","n":0,"m":"No off-hours privileged logon anomaly in last 24h","p":"Investigate off-hours privileged activity and enforce just-in-time administrative sessions.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Tier-1 hardening control deviation","o":"Tier-1 security hygiene and delegation checks","u":"Reduce delegation and harden configuration in the current remediation cycle."},"Privileged Infrastructure||Privileged Review: Public Key Services":{"c":"Privileged Infrastructure","r":"Privileged Review: Public Key Services","s":"Medium","n":1,"m":"Object not found or inaccessible","p":"PKI configuration objects define certificate trust behavior across the forest.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Public Key Services: Object could not be validated in directory [Medium]"]},"Privileged Infrastructure||Tier0: DCSync rights exposure":{"c":"Privileged Infrastructure","r":"Tier0: DCSync rights exposure","s":"Critical","n":4,"m":"NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS; BUILTIN\\Administrators; KUSO\\Enterprise Read-only Domain Controllers; KUSO\\Domain Controllers","p":"Restrict DS replication rights to built-in replication principals and remove delegated DCSync paths.","f":"MITRE ATT\u0026CK: T1003.006","d":["NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","BUILTIN\\Administrators: NC=DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","KUSO\\Enterprise Read-only Domain Controllers: NC=DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","KUSO\\Domain Controllers: NC=DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=CN=Configuration,DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=CN=Configuration,DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=CN=Configuration,DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=CN=Configuration,DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=CN=Configuration,DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=CN=Configuration,DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","KUSO\\Enterprise Read-only Domain Controllers: NC=CN=Configuration,DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","BUILTIN\\Administrators: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","BUILTIN\\Administrators: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","KUSO\\Enterprise Read-only Domain Controllers: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=89e95b76-444d-4c62-991a-0facbeda640c [Critical]","KUSO\\Enterprise Read-only Domain Controllers: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 [Critical]","KUSO\\Enterprise Read-only Domain Controllers: NC=CN=Schema,CN=Configuration,DC=kuso,DC=local, Right=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 [Critical]"],"a":"Non-replication principals have directory replication rights","o":"ACL extended rights on naming contexts","u":"Restrict DS replication rights to built-in replication principals only."},"Privileged Infrastructure||Tier1: DNS admin and zone transfer":{"c":"Privileged Infrastructure","r":"Tier1: DNS admin and zone transfer","s":"High","n":3,"m":"DnsAdmins=0; ZoneTransferRisk=3; 0.in-addr.arpa, 127.in-addr.arpa, 255.in-addr.arpa","p":"Minimize DnsAdmins membership and enforce secure zone transfer configuration.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"DNS administration and zone transfer posture can enable domain takeover paths","o":"DnsAdmins membership + DNS zone transfer settings","u":"Reduce DnsAdmins membership and enforce secure secondaries/no transfer."},"Privileged Accounts||RBCD exposure":{"c":"Privileged Accounts","r":"RBCD exposure","s":"Low","n":0,"m":"No RBCD object detected","p":"Review and minimize msDS-AllowedToActOnBehalfOfOtherIdentity on servers and especially DC-adjacent assets.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Resource-based constrained delegation risk","o":"msDS-AllowedToActOnBehalfOfOtherIdentity","u":"Limit RBCD ACLs with least privilege."},"Privileged Infrastructure||Privileged Review: Domain Controllers":{"c":"Privileged Infrastructure","r":"Privileged Review: Domain Controllers","s":"Critical","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Membership should only contain legitimate domain controller computer accounts.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Tier1: ESC8 - AD CS HTTP relay surface":{"c":"Privileged Infrastructure","r":"Tier1: ESC8 - AD CS HTTP relay surface","s":"Low","n":0,"m":"No reachable AD CS /certsrv endpoint detected","p":"Limit or disable AD CS web enrollment and harden NTLM relay protections on CA web endpoints.","f":"SpecterOps ESC8 / MITRE ATT\u0026CK: T1557.001","d":[],"a":"AD CS web enrollment endpoint can expose NTLM relay surface","o":"CA network reachability + /certsrv endpoint check","u":"Disable legacy web enrollment when possible and enforce EPA/TLS hardening where required."},"Privileged Infrastructure||LDAP signing posture":{"c":"Privileged Infrastructure","r":"LDAP signing posture","s":"Medium","n":2,"m":"KBDC01: LDAPServerIntegrity=1; KBSCCM: LDAPServerIntegrity=1","p":"Set LDAPServerIntegrity to enforce LDAP signing on domain controllers.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["KBDC01: LDAPServerIntegrity: 1 [Medium]","KBSCCM: LDAPServerIntegrity: 1 [Medium]"],"a":"LDAP signing is not strictly enforced on all domain controllers","o":"LDAPServerIntegrity under NTDS parameters","u":"Set LDAP signing requirement to enforce signed LDAP binds across DCs."},"Privileged Accounts||Recycle Bin disabled":{"c":"Privileged Accounts","r":"Recycle Bin disabled","s":"Medium","n":1,"m":"AD Recycle Bin is not enabled","p":"Enable AD Recycle Bin after change control and backup validation.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Forest: Recycle Bin optional feature is not enabled [Medium]"],"a":"AD Recycle Bin is not enabled","o":"Recycle Bin optional feature enabled scopes","u":"Enable AD Recycle Bin after impact assessment and backup validation."},"Privileged Infrastructure||Tier2: Computer object owner anomalies":{"c":"Privileged Infrastructure","r":"Tier2: Computer object owner anomalies","s":"Low","n":0,"m":"No DC computer object owner anomaly detected","p":"Set expected owner principals for Tier-0 computer objects and review delegated ACL changes.","f":"Tier-2 AD Baseline Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Unexpected owners on DC computer objects indicate delegation drift","o":"DC computer object ACL owner values","u":"Reset owner principals to approved Tier-0 administrators."},"Hygiene||Password never expires (enabled users)":{"c":"Hygiene","r":"Password never expires (enabled users)","s":"Medium","n":6,"m":"Administrator, exchadmin, sdogan, kbal","p":"Remove password-never-expires from regular accounts and apply exception process only where required.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Persistent password risk","o":"Enabled + PasswordNeverExpires attributes","u":"Remove password-never-expires from non-exception accounts."},"Privileged Accounts||Constrained delegation":{"c":"Privileged Accounts","r":"Constrained delegation","s":"Low","n":0,"m":"No constrained delegation object","p":"Review all constrained delegation paths and restrict to necessary SPNs only.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Delegation path exposure","o":"msDS-AllowedToDelegateTo","u":"Remove unnecessary SPN delegation paths."},"Anomalies||AS-REP roastable users":{"c":"Anomalies","r":"AS-REP roastable users","s":"Low","n":0,"m":"No AS-REP roastable user","p":"Disable DONT_REQ_PREAUTH on regular users and enforce strong password policy.","f":"CIS AD Benchmark: 1.1.5 / MITRE ATT\u0026CK: T1558.004","d":[],"a":"Offline cracking risk for pre-auth disabled accounts","o":"Get-ADUser LDAP: DONT_REQ_PREAUTH bit","u":"Require pre-authentication and harden password policy."},"Privileged Infrastructure||Tier2: Orphan and disabled GPO posture":{"c":"Privileged Infrastructure","r":"Tier2: Orphan and disabled GPO posture","s":"Low","n":0,"m":"Unlinked (never linked) GPO=0; Disabled/partial GPO=0; Sample=None","p":"Clean unlinked/disabled GPOs and reduce policy management noise.","f":"Tier-2 AD Baseline Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Unlinked or disabled GPOs create management drift and hidden risk","o":"GPO status and link inventory","u":"Clean unused GPOs and maintain a minimal active policy set."},"Privileged Infrastructure||Tier1: GPO owner anomalies":{"c":"Privileged Infrastructure","r":"Tier1: GPO owner anomalies","s":"Low","n":0,"m":"No Domain Users/Authenticated Users/Everyone GPO owner anomaly","p":"Set secure GPO ownership and remove broad principals from GPO owner chain.","f":"CIS Controls v8: 4.7 / MITRE ATT\u0026CK: T1484.001","d":[],"a":"GPO objects owned by broad identities can enable policy takeover","o":"GPO owner from AD ACL","u":"Set secure ownership for GPO objects and remove broad principals from owner chain."},"Privileged Infrastructure||Tiering violations":{"c":"Privileged Infrastructure","r":"Tiering violations","s":"High","n":1,"m":"administrator from KOKO (type 3)","p":"Restrict privileged account logons to tiered admin workstations and domain controllers only.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["administrator: Source=KOKO, LogonType=3, Seen=1, LastSeen=2026-04-05 15:33 [High]"],"a":"Privileged accounts authenticate from non-tiered endpoints","o":"4624 user-device visibility map filtered by privileged identities","u":"Restrict privileged logons to PAWs/DC administration tier and block workstation usage."},"Privileged Accounts||Privileged account with SPN":{"c":"Privileged Accounts","r":"Privileged account with SPN","s":"Low","n":0,"m":"No privileged account with SPN","p":"Move SPNs to gMSA/service accounts and keep privileged users free from SPN when possible.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Kerberoast exposure on privileged accounts","o":"Privileged group membership + servicePrincipalName","u":"Move SPNs to gMSA/service accounts."},"Privileged Accounts||Protected Users coverage":{"c":"Privileged Accounts","r":"Protected Users coverage","s":"High","n":4,"m":"Administrator, exchadmin, sdogan, rdemirhan","p":"Review privileged users not in Protected Users and add compatible accounts.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Administrator: Enabled privileged user is not in Protected Users [High]","exchadmin: Enabled privileged user is not in Protected Users [High]","sdogan: Enabled privileged user is not in Protected Users [High]","rdemirhan: Enabled privileged user is not in Protected Users [High]"],"a":"Privileged users outside Protected Users group","o":"Protected Users group membership vs privileged baseline","u":"Add eligible privileged users to Protected Users and validate compatibility."},"Privileged Infrastructure||DC spooler exposure":{"c":"Privileged Infrastructure","r":"DC spooler exposure","s":"High","n":2,"m":"KBDC01, KBSCCM","p":"Disable print spooler service on domain controllers.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["KBDC01: Spooler service is running [High]","KBSCCM: Spooler service is running [High]"],"a":"Spooler service running on domain controllers","o":"Win32_Service Spooler status on DCs","u":"Disable spooler on DCs unless strictly required."},"Privileged Accounts||Schema Admins populated":{"c":"Privileged Accounts","r":"Schema Admins populated","s":"Medium","n":4,"m":"rdemirhan, sdogan, exchadmin, Administrator","p":"Keep Schema Admins empty by default and use JIT elevation for schema operations.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["rdemirhan: Member of Schema Admins [Medium]","sdogan: Member of Schema Admins [Medium]","exchadmin: Member of Schema Admins [Medium]","Administrator: Member of Schema Admins [Medium]"],"a":"Schema Admins contains user accounts","o":"Schema Admins group membership","u":"Keep Schema Admins empty during normal operations and use temporary elevation when needed."},"Anomalies||Minimum password length":{"c":"Anomalies","r":"Minimum password length","s":"High","n":7,"m":"Minimum password length: 7","p":"Increase minimum password length (preferably 12+) and apply stronger fine-grained policies where needed.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Default Domain Password Policy: MinPasswordLength = 7 [High]"],"a":"Domain minimum password length policy","o":"Get-ADDefaultDomainPasswordPolicy MinPasswordLength","u":"Set minimum password length to at least 12 and apply stronger policy for service accounts."},"Privileged Infrastructure||Privileged Review: Backup Operators":{"c":"Privileged Infrastructure","r":"Privileged Review: Backup Operators","s":"High","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Backup privileges can bypass file ACL boundaries and expose sensitive data.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Anomalies||AD backup age":{"c":"Anomalies","r":"AD backup age","s":"Low","n":"N/A","m":"Backup metadata unavailable from DC event logs","p":"Run and monitor regular system state backups for domain controllers.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Potentially outdated AD backup posture","o":"Microsoft-Windows-Backup events on domain controllers","u":"Validate system state backup schedule and monitor last successful backup age."},"Privileged Infrastructure||Tier2: WinRM and RDP authorization scope":{"c":"Privileged Infrastructure","r":"Tier2: WinRM and RDP authorization scope","s":"Medium","n":2,"m":"KBDC01: RM=1,RDP=1; KBSCCM: RM=1,RDP=1","p":"Limit WinRM/RDP local group membership on domain controllers to approved admins only.","f":"Tier-2 AD Baseline Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Remote admin local groups on DCs may be broader than intended","o":"Remote Management Users and Remote Desktop Users local groups","u":"Restrict remote admin group membership to approved operators only."},"Privileged Accounts||Privileged accounts delegatable":{"c":"Privileged Accounts","r":"Privileged accounts delegatable","s":"High","n":4,"m":"Administrator, exchadmin, sdogan, rdemirhan","p":"Set AccountNotDelegated for privileged accounts unless explicitly required.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Administrator: Enabled privileged account can be delegated [High]","exchadmin: Enabled privileged account can be delegated [High]","sdogan: Enabled privileged account can be delegated [High]","rdemirhan: Enabled privileged account can be delegated [High]"],"a":"Privileged account delegation exposure","o":"Privileged account AccountNotDelegated flag","u":"Set AccountNotDelegated for privileged users and review delegation requirements."},"Privileged Infrastructure||Privileged Review: Certificate Publishers":{"c":"Privileged Infrastructure","r":"Privileged Review: Certificate Publishers","s":"Medium","n":1,"m":"Object not found or inaccessible","p":"Publishing certificate data can indirectly affect authentication hygiene. Group cannot be resolved or access is denied.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Certificate Publishers: Object could not be validated in directory [Medium]"]},"Privileged Infrastructure||Privileged Review: DC=kuso,DC=local":{"c":"Privileged Infrastructure","r":"Privileged Review: DC=kuso,DC=local","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Domain root ACL and delegated links can create indirect control paths.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Shadow admin exposure":{"c":"Privileged Infrastructure","r":"Shadow admin exposure","s":"High","n":4,"m":"Group Policy Creator Owners: exposure=4","p":"Review delegated operator groups and remove non-essential members and nested control paths.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Group Policy Creator Owners: Users=4, Computers=0, Indirect=0, Unresolved=0 [High]"],"a":"Delegated operator groups may provide indirect privileged control","o":"Privileged group review rows (operators, DNS/GPO/key admins)","u":"Empty high-risk delegated groups and restrict delegated rights with tiered admin model."},"Privileged Infrastructure||Privileged Review: Key Admins":{"c":"Privileged Infrastructure","r":"Privileged Review: Key Admins","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Key admin roles should be isolated and protected by strong monitoring.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: AdminSDHolder":{"c":"Privileged Infrastructure","r":"Privileged Review: AdminSDHolder","s":"Critical","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"AdminSDHolder ACL controls protected accounts and must be hardened.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Old NTLM posture":{"c":"Privileged Infrastructure","r":"Old NTLM posture","s":"High","n":2,"m":"KBDC01: LmCompatibilityLevel=; KBSCCM: LmCompatibilityLevel=","p":"Set LmCompatibilityLevel to 5 on DCs and disable legacy NTLM protocols.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["KBDC01: LmCompatibilityLevel:  [High]","KBSCCM: LmCompatibilityLevel:  [High]"],"a":"LM/NTLMv1 compatibility may still be allowed","o":"LmCompatibilityLevel on DC registry","u":"Set LmCompatibilityLevel to 5 and phase out legacy NTLM."},"Privileged Infrastructure||Tier1: Shadow credentials exposure":{"c":"Privileged Infrastructure","r":"Tier1: Shadow credentials exposure","s":"Low","n":0,"m":"No object with msDS-KeyCredentialLink found","p":"Review WHfB key credentials and restrict write permissions to msDS-KeyCredentialLink.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Objects carry key credentials that may allow stealthy auth abuse","o":"msDS-KeyCredentialLink on users/computers","u":"Audit key credentials and restrict write access to msDS-KeyCredentialLink."},"Anomalies||DC coercion exposure":{"c":"Anomalies","r":"DC coercion exposure","s":"High","n":2,"m":"Potential coercion path indicator (spooler running): KBDC01, KBSCCM","p":"Harden RPC coercion paths and reduce exposed printer-related interfaces.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["KBDC01: Spooler status indicates common coercion precondition [High]","KBSCCM: Spooler status indicates common coercion precondition [High]"],"a":"Domain controllers exposed to common coercion prerequisites","o":"Spooler remote status indicator on DCs","u":"Harden coercion paths and disable unnecessary RPC attack surfaces."},"Trusts||Trust posture":{"c":"Trusts","r":"Trust posture","s":"Low","n":0,"m":"No trust relation found or trust data unavailable","p":"Enable SID filtering, disable unnecessary TGT delegation, and review selective authentication.","f":"MITRE ATT\u0026CK: T1484.002","d":[],"a":"Trust security configuration risk","o":"Get-ADTrust: SIDFiltering/TGTDelegation/SelectiveAuthentication","u":"Enable SID filtering, disable unnecessary TGT delegation, and review selective authentication."},"Anomalies||krbtgt password age":{"c":"Anomalies","r":"krbtgt password age","s":"Critical","n":681,"m":"krbtgt password age: 681 days","p":"Rotate krbtgt password in a controlled 2-step process and document rotation cadence.","f":"ANSSI AD Security Guide / MITRE ATT\u0026CK: T1558.001","d":["krbtgt: 681 days since last password set [Critical]"],"a":"Golden Ticket risk tied to krbtgt password age","o":"Get-ADUser krbtgt PasswordLastSet","u":"Apply a planned two-step krbtgt rotation procedure."},"Privileged Infrastructure||Privileged Review: Administrator":{"c":"Privileged Infrastructure","r":"Privileged Review: Administrator","s":"Critical","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Built-in Administrator should be protected, monitored and rarely used.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: Schema Admins":{"c":"Privileged Infrastructure","r":"Privileged Review: Schema Admins","s":"Critical","n":4,"m":"Users=4, Computers=0, Indirect=0, Unresolved=0","p":"Schema changes are high-impact and should be temporary, approved and audited.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Schema Admins: User members: 4 [Critical]"]},"Privileged Infrastructure||Privileged Review: Domain Admins":{"c":"Privileged Infrastructure","r":"Privileged Review: Domain Admins","s":"Critical","n":4,"m":"Users=4, Computers=0, Indirect=0, Unresolved=0","p":"Domain-wide administrative rights should be tightly limited and controlled.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Domain Admins: User members: 4 [Critical]"]},"Privileged Infrastructure||Privileged Review: Enterprise Admins":{"c":"Privileged Infrastructure","r":"Privileged Review: Enterprise Admins","s":"Critical","n":4,"m":"Users=4, Computers=0, Indirect=0, Unresolved=0","p":"Forest-wide administrative rights should remain minimal and break-glass only.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Enterprise Admins: User members: 4 [Critical]"]},"Privileged Infrastructure||Tier1: SYSVOL and NETLOGON posture":{"c":"Privileged Infrastructure","r":"Tier1: SYSVOL and NETLOGON posture","s":"Low","n":0,"m":"FRS running on 0 DC(s); GPP cpassword files=0; NETLOGON sensitive hits=0","p":"Use DFS-R only, remove credential residues from SYSVOL/NETLOGON, and monitor script shares.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"SYSVOL/NETLOGON may contain insecure replication or credential residue","o":"FRS service state + sensitive content scan","u":"Use DFS-R only and remove sensitive scripts/config from shared policy paths."},"Stale Objects||LAPS coverage":{"c":"Stale Objects","r":"LAPS coverage","s":"Low","n":0,"m":"LAPS check could not be completed","p":"Track Legacy LAPS and Windows LAPS v2 separately and enforce endpoint coverage with expiration monitoring.","f":"CIS AD Benchmark: 1.1.3","d":[],"a":"Endpoint local admin password coverage risk","o":"msLAPS/ms-Mcs-AdmPwdExpirationTime attributes","u":"Increase LAPS coverage and enforce expiration tracking."},"Privileged Infrastructure||Privileged Review: Server Operators":{"c":"Privileged Infrastructure","r":"Privileged Review: Server Operators","s":"High","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Server operators can perform service-level changes that impact domain security.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Accounts||Native admin recent login":{"c":"Privileged Accounts","r":"Native admin recent login","s":"High","n":2,"m":"Builtin admin last logon: 2 day(s) ago","p":"Limit usage of builtin admin and prefer dedicated tiered admin accounts.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Administrator: 2 day(s) since last logon [High]"],"a":"Builtin Administrator account was used recently","o":"Builtin admin (RID 500) LastLogonTimestamp","u":"Avoid daily use of builtin admin and use tiered/jit admin accounts."},"Privileged Infrastructure||LDAP channel binding posture":{"c":"Privileged Infrastructure","r":"LDAP channel binding posture","s":"High","n":2,"m":"KBDC01: LdapEnforceChannelBinding=; KBSCCM: LdapEnforceChannelBinding=","p":"Set LdapEnforceChannelBinding to a protected mode and validate client compatibility.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["KBDC01: LdapEnforceChannelBinding:  [High]","KBSCCM: LdapEnforceChannelBinding:  [High]"],"a":"LDAP channel binding may not be enforced","o":"LdapEnforceChannelBinding under NTDS parameters","u":"Enable LDAP channel binding policy and validate application compatibility."},"Privileged Infrastructure||Tier1: Inactive or orphan service accounts":{"c":"Privileged Infrastructure","r":"Tier1: Inactive or orphan service accounts","s":"Low","n":0,"m":"No stale/disabled SPN service account detected","p":"Disable or clean stale SPN accounts and migrate service identities to managed models.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Dormant SPN accounts increase credential theft and persistence risk","o":"SPN user account status and logon recency","u":"Disable unused SPN accounts and migrate to managed service accounts."},"Privileged Infrastructure||Tier0: Tier model violations":{"c":"Privileged Infrastructure","r":"Tier0: Tier model violations","s":"Critical","n":1,"m":"administrator from KOKO (type 3)","p":"Separate Tier-0 and Tier-1 administration paths and enforce PAW usage for privileged identities.","f":"Tier-0 AD Security Control / MITRE ATT\u0026CK technique mapping required","d":[],"a":"Privileged identities authenticate from non-tier endpoints","o":"Privileged user-device authentication telemetry","u":"Enforce tiered admin model and privileged access workstation boundaries."},"Privileged Infrastructure||Privileged Review: krbtgt":{"c":"Privileged Infrastructure","r":"Privileged Review: krbtgt","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"krbtgt account lifecycle and password rotations are critical against ticket forgery.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: Administrators":{"c":"Privileged Infrastructure","r":"Privileged Review: Administrators","s":"Critical","n":7,"m":"Users=4, Computers=0, Indirect=3, Unresolved=0","p":"Builtin Administrators grants extensive control on domain controllers and critical systems.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Administrators: User members: 4 [Critical]","Administrators: Indirect control groups: 3 [Critical]"]},"Trusts||SIDHistory usage":{"c":"Trusts","r":"SIDHistory usage","s":"Low","n":0,"m":"No SIDHistory usage detected","p":"Review and remove unnecessary SIDHistory values, especially after migration projects.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"SIDHistory residual abuse risk","o":"Get-ADUser/Get-ADGroup SIDHistory attribute","u":"Clean unnecessary SIDHistory values and remove migration leftovers."},"Privileged Infrastructure||Tier2: FGPP coverage for privileged accounts":{"c":"Privileged Infrastructure","r":"Tier2: FGPP coverage for privileged accounts","s":"Low","n":0,"m":"FGPP coverage appears acceptable or no FGPP configured","p":"Apply stricter fine-grained password policies to privileged identities.","f":"Tier-2 AD Baseline Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Privileged accounts may not be covered by stricter fine-grained policies","o":"Resultant FGPP checks on privileged identities","u":"Apply dedicated FGPP to privileged users."},"Privileged Infrastructure||Privileged Review: Read-only Domain Controllers":{"c":"Privileged Infrastructure","r":"Privileged Review: Read-only Domain Controllers","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"RODC group membership should reflect actual deployment and branch office design.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: DnsAdmins":{"c":"Privileged Infrastructure","r":"Privileged Review: DnsAdmins","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"DNS admins can influence name resolution and potentially abuse DC plugin loading paths.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: Print Operators":{"c":"Privileged Infrastructure","r":"Privileged Review: Print Operators","s":"High","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Print-related rights on DCs have historically enabled privilege escalation paths.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Tier1: gMSA adoption":{"c":"Privileged Infrastructure","r":"Tier1: gMSA adoption","s":"Low","n":0,"m":"gMSA=0, SPN users=0, legacy service identities=0","p":"Increase gMSA usage and reduce password-managed service accounts.","f":"Tier-1 AD Hardening Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Low gMSA adoption indicates password-managed service account debt","o":"gMSA inventory compared to SPN user accounts","u":"Increase gMSA coverage for eligible services."},"Anomalies||DC audit posture":{"c":"Anomalies","r":"DC audit posture","s":"Low","n":0,"m":"Audit policy appears present on reachable DCs","p":"Enable and verify advanced audit policy baseline on all domain controllers.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[],"a":"Domain controller audit policy may be incomplete","o":"auditpol /get /category:* on DCs","u":"Enable advanced audit coverage for account logon, DS access and policy change."},"Privileged Infrastructure||Privileged Review: Computers":{"c":"Privileged Infrastructure","r":"Privileged Review: Computers","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Default Computers container delegation should be reviewed for abuse paths.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Tier2: SMB and LDAP signing baseline":{"c":"Privileged Infrastructure","r":"Tier2: SMB and LDAP signing baseline","s":"Medium","n":4,"m":"SMB signing issues=0; LDAP signing issues=2; LDAP channel binding issues=2","p":"Enforce SMB signing, LDAP signing and channel binding across all domain controllers.","f":"Tier-2 AD Baseline Control / MITRE ATT\u0026CK mapping required","d":[],"a":"Transport/integrity hardening baseline is incomplete on DCs","o":"SMB signing and LDAP signing/channel binding registry checks","u":"Enforce SMB signing and LDAP signing/channel binding domain-wide."},"Privileged Infrastructure||Privileged Review: Enterprise Read-only Domain Controllers":{"c":"Privileged Infrastructure","r":"Privileged Review: Enterprise Read-only Domain Controllers","s":"Low","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Review membership to ensure only intended RODC computer accounts are present.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Accounts||Unconstrained delegation":{"c":"Privileged Accounts","r":"Unconstrained delegation","s":"Critical","n":2,"m":"KBDC01, KBSCCM","p":"Remove unconstrained delegation and use constrained delegation or gMSA patterns.","f":"CIS AD Benchmark: 1.1.8 / MITRE ATT\u0026CK: T1558.003","d":["KBDC01: Computer trusted for delegation [Critical]","KBSCCM: Computer trusted for delegation [Critical]"],"a":"High lateral movement risk via ticket forwarding","o":"TrustedForDelegation and UAC delegation flags","u":"Remove unconstrained delegation and move to constrained model."},"Privileged Infrastructure||Tier0: ESC4 - Template ACL write abuse":{"c":"Privileged Infrastructure","r":"Tier0: ESC4 - Template ACL write abuse","s":"Low","n":0,"m":"Check could not be completed","p":"Control unavailable: review template ACL permissions manually.","f":"SpecterOps ESC4 / MITRE ATT\u0026CK: T1484.001","d":[],"a":"Broad principals can modify certificate template ACL/owner/rights","o":"nTSecurityDescriptor on certificate templates","u":"Remove dangerous write rights from broad groups and delegate template management to dedicated PKI admins."},"Privileged Infrastructure||Tier0: ESC6 - SAN attribute injection flag":{"c":"Privileged Infrastructure","r":"Tier0: ESC6 - SAN attribute injection flag","s":"Low","n":0,"m":"No ESC6 flag detected on reachable CA servers","p":"Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on enterprise CAs unless strictly required and governed.","f":"SpecterOps ESC6 / MITRE ATT\u0026CK: T1550","d":[],"a":"CA EditFlags allows SAN injection through request attributes","o":"CA registry EditFlags on CertSvc","u":"Disable EDITF_ATTRIBUTESUBJECTALTNAME2 and enforce SAN via template/approved issuance policy only."},"Privileged Infrastructure||Tier0: NTLMv1 active usage":{"c":"Privileged Infrastructure","r":"Tier0: NTLMv1 active usage","s":"Low","n":0,"m":"No NTLMv1 logon evidence in sampled 4624 events","p":"Identify NTLMv1 clients, enforce NTLM hardening and eliminate legacy authentication paths.","f":"Tier-0 AD Security Control / MITRE ATT\u0026CK technique mapping required","d":[],"a":"Observed NTLMv1 authentication in DC security logs","o":"Security event 4624 LM package values","u":"Identify legacy clients and enforce NTLM hardening to eliminate NTLMv1."},"Stale Objects||Weak Kerberos encryption":{"c":"Stale Objects","r":"Weak Kerberos encryption","s":"High","n":1,"m":"krbtgt","p":"Prefer AES encryption types and remove DES/legacy settings from service accounts.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["krbtgt: msDS-SupportedEncryptionTypes: 0 [High]"],"a":"Legacy Kerberos encryption usage","o":"msDS-SupportedEncryptionTypes","u":"Move to AES-focused encryption settings and disable DES/legacy."},"Privileged Infrastructure||Privileged Review: Builtin":{"c":"Privileged Infrastructure","r":"Privileged Review: Builtin","s":"Medium","n":0,"m":"Users=0, Computers=0, Indirect=0, Unresolved=0","p":"Builtin container content should be reviewed for delegated administrative access.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":[]},"Privileged Infrastructure||Privileged Review: Certificate Operators":{"c":"Privileged Infrastructure","r":"Privileged Review: Certificate Operators","s":"Medium","n":1,"m":"Object not found or inaccessible","p":"Certificate-related operations can impact PKI trust and authentication paths. Group cannot be resolved or access is denied.","f":"CIS AD Benchmark / MITRE ATT\u0026CK mapping review required","d":["Certificate Operators: Object could not be validated in directory [Medium]"]},"Privileged Infrastructure||Tier0: ESC1 - Enrollee supplies subject":{"c":"Privileged Infrastructure","r":"Tier0: ESC1 - Enrollee supplies subject","s":"Low","n":0,"m":"Check could not be completed","p":"Control unavailable: verify certificate template ESC1 conditions manually.","f":"SpecterOps ESC1 / MITRE ATT\u0026CK: T1552, T1649","d":[],"a":"AD CS template allows subject supply with auth EKU and risky enrollment flags","o":"Certificate Templates in Configuration partition","u":"Disable enrollee-supplied subject on authentication templates and tighten enrollment controls."}};
var quickRemediationItems = [{"Key":"Privileged Infrastructure|Harden Tier-0 assets first: lock down Domain Controllers, sensitive groups, and certificate infrastructure delegation.","Category":"Privileged Infrastructure","RiskPct":100,"Action":"Harden Tier-0 assets first: lock down Domain Controllers, sensitive groups, and certificate infrastructure delegation.","CurrentStatus":"open","CurrentNote":"","UpdatedAt":""},{"Key":"Certificate Authority|Harden AD CS/CA quickly: close ESC paths, narrow template ACLs, and restrict enrollment scope to least privilege.","Category":"Certificate Authority","RiskPct":100,"Action":"Harden AD CS/CA quickly: close ESC paths, narrow template ACLs, and restrict enrollment scope to least privilege.","CurrentStatus":"open","CurrentNote":"","UpdatedAt":""},{"Key":"Privileged Accounts|Reduce standing privilege: remove unnecessary admin rights, enforce PAW/JIT model, and rotate privileged credentials.","Category":"Privileged Accounts","RiskPct":67,"Action":"Reduce standing privilege: remove unnecessary admin rights, enforce PAW/JIT model, and rotate privileged credentials.","CurrentStatus":"open","CurrentNote":"","UpdatedAt":""}];
var remediationBaselineStates = [];
var priorityRiskFindings = [{"Category":"Anomalies","Severity":"Critical","Rule":"krbtgt password age","Count":681,"Sample":"krbtgt password age: 681 days","Recommendation":"Rotate krbtgt password in a controlled 2-step process and document rotation cadence."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Tier0: Dangerous ACE on critical objects","Count":28,"Sample":"NT AUTHORITY\\SYSTEM on DC=kuso,DC=local [GenericAll]; BUILTIN\\Administrators on DC=kuso,DC=local [WriteDacl,WriteOwner]; KUSO\\Domain Admins on DC=kuso,DC=local [WriteDacl,WriteOwner]; KUSO\\Enterprise Admins on DC=kuso,DC=local [GenericAll]; KUSO\\Organization Management on DC=kuso,DC=local [GenericAll]","Recommendation":"Remove non-essential GenericAll/GenericWrite/WriteDacl/WriteOwner ACEs from Tier-0 objects."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Privileged Review: Administrators","Count":7,"Sample":"Users=4, Computers=0, Indirect=3, Unresolved=0","Recommendation":"Builtin Administrators grants extensive control on domain controllers and critical systems."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Tier0: DCSync rights exposure","Count":4,"Sample":"NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS; BUILTIN\\Administrators; KUSO\\Enterprise Read-only Domain Controllers; KUSO\\Domain Controllers","Recommendation":"Restrict DS replication rights to built-in replication principals and remove delegated DCSync paths."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Privileged Review: Schema Admins","Count":4,"Sample":"Users=4, Computers=0, Indirect=0, Unresolved=0","Recommendation":"Schema changes are high-impact and should be temporary, approved and audited."}];
var caRiskRows = [{"Category":"Anomalies","Severity":"Critical","Rule":"krbtgt password age","Count":681,"Sample":"krbtgt password age: 681 days","Recommendation":"Rotate krbtgt password in a controlled 2-step process and document rotation cadence."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Tier0: Dangerous ACE on critical objects","Count":28,"Sample":"NT AUTHORITY\\SYSTEM on DC=kuso,DC=local [GenericAll]; BUILTIN\\Administrators on DC=kuso,DC=local [WriteDacl,WriteOwner]; KUSO\\Domain Admins on DC=kuso,DC=local [WriteDacl,WriteOwner]; KUSO\\Enterprise Admins on DC=kuso,DC=local [GenericAll]; KUSO\\Organization Management on DC=kuso,DC=local [GenericAll]","Recommendation":"Remove non-essential GenericAll/GenericWrite/WriteDacl/WriteOwner ACEs from Tier-0 objects."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Privileged Review: Administrators","Count":7,"Sample":"Users=4, Computers=0, Indirect=3, Unresolved=0","Recommendation":"Builtin Administrators grants extensive control on domain controllers and critical systems."},{"Category":"Privileged Infrastructure","Severity":"Critical","Rule":"Tier0: DCSync rights exposure","Count":4,"Sample":"NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS; BUILTIN\\Administrators; KUSO\\Enterprise Read-only Domain Controllers; KUSO\\Domain Controllers","Recommendation":"Restrict DS replication rights to built-in replication principals and remove delegated DCSync paths."},{"Category":"Privileged Accounts","Severity":"High","Rule":"Native admin recent login","Count":2,"Sample":"Builtin admin last logon: 2 day(s) ago","Recommendation":"Limit usage of builtin admin and prefer dedicated tiered admin accounts."},{"Category":"Privileged Infrastructure","Severity":"Medium","Rule":"Privileged Review: Group Policy Creator Owners","Count":4,"Sample":"Users=4, Computers=0, Indirect=0, Unresolved=0","Recommendation":"GPO creation rights can enable broad policy abuse if not constrained."},{"Category":"Privileged Infrastructure","Severity":"Medium","Rule":"Tier2: WinRM and RDP authorization scope","Count":2,"Sample":"KBDC01: RM=1,RDP=1; KBSCCM: RM=1,RDP=1","Recommendation":"Limit WinRM/RDP local group membership on domain controllers to approved admins only."},{"Category":"Privileged Accounts","Severity":"Medium","Rule":"adminCount drift","Count":1,"Sample":"krbtgt","Recommendation":"Review adminCount=1 accounts outside privileged groups and fix ACL inheritance where applicable."},{"Category":"Privileged Infrastructure","Severity":"Medium","Rule":"Privileged Review: Public Key Services","Count":1,"Sample":"Object not found or inaccessible","Recommendation":"PKI configuration objects define certificate trust behavior across the forest."},{"Category":"Privileged Infrastructure","Severity":"Medium","Rule":"Privileged Review: Certificate Operators","Count":1,"Sample":"Object not found or inaccessible","Recommendation":"Certificate-related operations can impact PKI trust and authentication paths. Group cannot be resolved or access is denied."},{"Category":"Privileged Infrastructure","Severity":"Medium","Rule":"Privileged Review: Certificate Publishers","Count":1,"Sample":"Object not found or inaccessible","Recommendation":"Publishing certificate data can indirectly affect authentication hygiene. Group cannot be resolved or access is denied."}];
var mitreRows = [{"Category":"Anomalies","Rule":"krbtgt password age","Severity":"Critical","Tactics":["TA0005 Defense Evasion","TA0007 Discovery"],"Techniques":["T1069 Permission Groups Discovery","T1087 Account Discovery"]},{"Category":"Privileged Accounts","Rule":"Unconstrained delegation","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Stale Objects","Rule":"Weak Kerberos encryption","Severity":"High","Tactics":["TA0003 Persistence","TA0008 Lateral Movement"],"Techniques":["T1078 Valid Accounts","T1136 Create Account"]},{"Category":"Hygiene","Rule":"Password never expires (enabled users)","Severity":"Medium","Tactics":["TA0005 Defense Evasion","TA0007 Discovery"],"Techniques":["T1562 Impair Defenses","T1070 Indicator Removal"]},{"Category":"Privileged Accounts","Rule":"adminCount drift","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Privileged Accounts","Rule":"Privileged accounts delegatable","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Privileged Accounts","Rule":"Protected Users coverage","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Privileged Accounts","Rule":"Schema Admins populated","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Privileged Accounts","Rule":"Recycle Bin disabled","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Anomalies","Rule":"Minimum password length","Severity":"High","Tactics":["TA0005 Defense Evasion","TA0007 Discovery"],"Techniques":["T1069 Permission Groups Discovery","T1087 Account Discovery"]},{"Category":"Privileged Accounts","Rule":"Native admin recent login","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0006 Credential Access"],"Techniques":["T1078 Valid Accounts","T1098 Account Manipulation"]},{"Category":"Privileged Infrastructure","Rule":"DC spooler exposure","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Anomalies","Rule":"DC coercion exposure","Severity":"High","Tactics":["TA0005 Defense Evasion","TA0007 Discovery"],"Techniques":["T1069 Permission Groups Discovery","T1087 Account Discovery"]},{"Category":"Privileged Infrastructure","Rule":"Old NTLM posture","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"LDAP signing posture","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"LDAP channel binding posture","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Shadow admin exposure","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tiering violations","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier0: DCSync rights exposure","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier0: Dangerous ACE on critical objects","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier0: Tier model violations","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier1: Pre-Windows 2000 compatible access","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier1: DNS admin and zone transfer","Severity":"High","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier2: SMB and LDAP signing baseline","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Tier2: WinRM and RDP authorization scope","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Administrators","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Certificate Operators","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Certificate Publishers","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Domain Admins","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Enterprise Admins","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Group Policy Creator Owners","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Schema Admins","Severity":"Critical","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Public Key Services","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Group Policy Creator Owners","Severity":"Medium","Tactics":["TA0003 Persistence","TA0004 Privilege Escalation","TA0005 Defense Evasion"],"Techniques":["T1484 Domain Policy Modification","T1558 Steal or Forge Kerberos Tickets"]}];
var threatPriorityRows = [{"Rule":"krbtgt password age","Category":"Anomalies","Severity":"Critical","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1069 Permission Groups Discovery","PriorityScore":100},{"Rule":"Unconstrained delegation","Category":"Privileged Accounts","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":100},{"Rule":"krbtgt password age","Category":"Anomalies","Severity":"Critical","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1087 Account Discovery","PriorityScore":100},{"Rule":"Unconstrained delegation","Category":"Privileged Accounts","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":100},{"Rule":"Privileged Review: Administrators","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Privileged Review: Domain Admins","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Privileged Review: Enterprise Admins","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Privileged Review: Schema Admins","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Tier0: Dangerous ACE on critical objects","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Tier0: DCSync rights exposure","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Tier0: Tier model violations","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":100},{"Rule":"Privileged Review: Administrators","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"Privileged Review: Domain Admins","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"Privileged Review: Enterprise Admins","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"Privileged Review: Schema Admins","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"Tier0: Dangerous ACE on critical objects","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"Tier0: DCSync rights exposure","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"Tier0: Tier model violations","Category":"Privileged Infrastructure","Severity":"Critical","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":100},{"Rule":"DC coercion exposure","Category":"Anomalies","Severity":"High","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1069 Permission Groups Discovery","PriorityScore":80},{"Rule":"Minimum password length","Category":"Anomalies","Severity":"High","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1069 Permission Groups Discovery","PriorityScore":80},{"Rule":"Native admin recent login","Category":"Privileged Accounts","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":80},{"Rule":"Privileged accounts delegatable","Category":"Privileged Accounts","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":80},{"Rule":"Protected Users coverage","Category":"Privileged Accounts","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":80},{"Rule":"Weak Kerberos encryption","Category":"Stale Objects","Severity":"High","Tactics":"TA0003 Persistence, TA0008 Lateral Movement","Technique":"T1078 Valid Accounts","PriorityScore":80},{"Rule":"DC coercion exposure","Category":"Anomalies","Severity":"High","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1087 Account Discovery","PriorityScore":80},{"Rule":"Minimum password length","Category":"Anomalies","Severity":"High","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1087 Account Discovery","PriorityScore":80},{"Rule":"Native admin recent login","Category":"Privileged Accounts","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":80},{"Rule":"Privileged accounts delegatable","Category":"Privileged Accounts","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":80},{"Rule":"Protected Users coverage","Category":"Privileged Accounts","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":80},{"Rule":"Weak Kerberos encryption","Category":"Stale Objects","Severity":"High","Tactics":"TA0003 Persistence, TA0008 Lateral Movement","Technique":"T1136 Create Account","PriorityScore":80},{"Rule":"DC spooler exposure","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"LDAP channel binding posture","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"Old NTLM posture","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"Shadow admin exposure","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"Tier1: DNS admin and zone transfer","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"Tier1: Pre-Windows 2000 compatible access","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"Tiering violations","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":80},{"Rule":"DC spooler exposure","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"LDAP channel binding posture","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"Old NTLM posture","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"Shadow admin exposure","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"Tier1: DNS admin and zone transfer","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"Tier1: Pre-Windows 2000 compatible access","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"Tiering violations","Category":"Privileged Infrastructure","Severity":"High","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":80},{"Rule":"Password never expires (enabled users)","Category":"Hygiene","Severity":"Medium","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1070 Indicator Removal","PriorityScore":55},{"Rule":"adminCount drift","Category":"Privileged Accounts","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":55},{"Rule":"Recycle Bin disabled","Category":"Privileged Accounts","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":55},{"Rule":"Schema Admins populated","Category":"Privileged Accounts","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1078 Valid Accounts","PriorityScore":55},{"Rule":"adminCount drift","Category":"Privileged Accounts","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":55},{"Rule":"Recycle Bin disabled","Category":"Privileged Accounts","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":55},{"Rule":"Schema Admins populated","Category":"Privileged Accounts","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0006 Credential Access","Technique":"T1098 Account Manipulation","PriorityScore":55},{"Rule":"LDAP signing posture","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Privileged Review: Certificate Operators","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Privileged Review: Certificate Publishers","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Privileged Review: Group Policy Creator Owners","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Privileged Review: Group Policy Creator Owners","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Privileged Review: Public Key Services","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Tier2: SMB and LDAP signing baseline","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"Tier2: WinRM and RDP authorization scope","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1484 Domain Policy Modification","PriorityScore":55},{"Rule":"LDAP signing posture","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Privileged Review: Certificate Operators","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Privileged Review: Certificate Publishers","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Privileged Review: Group Policy Creator Owners","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Privileged Review: Group Policy Creator Owners","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Privileged Review: Public Key Services","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Tier2: SMB and LDAP signing baseline","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Tier2: WinRM and RDP authorization scope","Category":"Privileged Infrastructure","Severity":"Medium","Tactics":"TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion","Technique":"T1558 Steal or Forge Kerberos Tickets","PriorityScore":55},{"Rule":"Password never expires (enabled users)","Category":"Hygiene","Severity":"Medium","Tactics":"TA0005 Defense Evasion, TA0007 Discovery","Technique":"T1562 Impair Defenses","PriorityScore":55}];
var attackChainNodes = [{"Category":"Anomalies","Rule":"krbtgt password age","Severity":"Critical"},{"Category":"Privileged Infrastructure","Rule":"Tier0: Dangerous ACE on critical objects","Severity":"Critical"},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Administrators","Severity":"Critical"},{"Category":"Privileged Infrastructure","Rule":"Tier0: DCSync rights exposure","Severity":"Critical"},{"Category":"Privileged Infrastructure","Rule":"Privileged Review: Schema Admins","Severity":"Critical"}];
var attackChainScenarios = [{"ScenarioName":"Coercion to DA","Steps":["DC spooler exposure","Unconstrained delegation","krbtgt password age"],"Risk":"Critical","Description":"Spooler + unconstrained delegation = NTLM coercion to TGT capture path with DA takeover potential.","Matched":true,"Evidence":["DC spooler exposure","DC coercion exposure","Unconstrained delegation"]},{"ScenarioName":"Shadow Admin Path","Steps":["Shadow admin exposure","adminCount drift","DCSync","domain takeover"],"Risk":"Critical","Description":"Shadow admin posture plus adminCount or DCSync drift creates a hidden domain takeover route.","Matched":true,"Evidence":["Shadow admin exposureadminCount drift AdminCount drift"]},{"ScenarioName":"Legacy Auth Relay","Steps":["NTLM legacy posture","LDAP relay weakness","credential capture"],"Risk":"High","Description":"Legacy NTLM posture with LDAP signing/channel-binding weakness allows relay and credential capture opportunities.","Matched":true,"Evidence":["Old NTLM postureLDAP signing posture LDAP channel binding posture"]}];
var riskTrendSeries = [{"GeneratedAt":"2026-04-03 12:00:46","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 12:03:43","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 12:04:42","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 12:03:19","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-03 12:13:37","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-03 13:19:15","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-03 13:30:34","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 13:38:28","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 13:42:34","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 13:42:04","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 13:44:38","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 13:57:28","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 13:58:29","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:06:43","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:05:57","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:07:46","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:16:36","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:17:37","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:16:17","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:21:46","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:26:22","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:24:52","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:27:26","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:34:34","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:40:26","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:47:38","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 14:51:13","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 15:02:54","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-03 15:11:10","DomainRiskScore":54,"RiskRating":"Acceptable","Critical":11,"High":16,"Medium":20},{"GeneratedAt":"2026-04-05 15:50:34","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-05 15:54:35","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-05 16:36:43","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-05 16:40:28","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-05 16:43:52","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-05 16:48:17","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20},{"GeneratedAt":"2026-04-05 16:49:21","DomainRiskScore":56,"RiskRating":"Acceptable","Critical":12,"High":17,"Medium":20}];
var UserRiskActivity = [{"TimeIso":"2026-04-03T11:45:15.2194546+03:00","TimeDisplay":"03/04/2026 11:45:15","Status":"Success","User":"administrator","SourceHost":"KBDC01","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"7","Reason":"-"},{"TimeIso":"2026-04-03T11:45:13.0445199+03:00","TimeDisplay":"03/04/2026 11:45:13","Status":"Success","User":"Administrator","SourceHost":"KOKO","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"3","Reason":"-"},{"TimeIso":"2026-04-03T10:25:24.5781226+03:00","TimeDisplay":"03/04/2026 10:25:24","Status":"Failed","User":"sccm_test","SourceHost":"KBSCCM","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:25:22.4639551+03:00","TimeDisplay":"03/04/2026 10:25:22","Status":"Failed","User":"sccm_test","SourceHost":"KBSCCM","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:25:20.3526068+03:00","TimeDisplay":"03/04/2026 10:25:20","Status":"Failed","User":"sccm_test","SourceHost":"KBSCCM","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:20:49.1850254+03:00","TimeDisplay":"03/04/2026 10:20:49","Status":"Failed","User":"testuser_wrong","SourceHost":"KBDC01","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:20:47.1422426+03:00","TimeDisplay":"03/04/2026 10:20:47","Status":"Failed","User":"testuser_wrong","SourceHost":"KBDC01","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:20:45.1061249+03:00","TimeDisplay":"03/04/2026 10:20:45","Status":"Failed","User":"testuser_wrong","SourceHost":"KBDC01","SourceIP":"-","DestinationHost":"KBDC01","DestinationIP":"10.210.9.90","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:20:21.6505014+03:00","TimeDisplay":"03/04/2026 10:20:21","Status":"Failed","User":"kbal","SourceHost":"KOKO","SourceIP":"-","DestinationHost":"KBSCCM","DestinationIP":"10.210.9.92","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:20:19.5236938+03:00","TimeDisplay":"03/04/2026 10:20:19","Status":"Failed","User":"kbal","SourceHost":"KOKO","SourceIP":"-","DestinationHost":"KBSCCM","DestinationIP":"10.210.9.92","LogonType":"-","Reason":"Logon failed"},{"TimeIso":"2026-04-03T10:20:16.6687650+03:00","TimeDisplay":"03/04/2026 10:20:16","Status":"Failed","User":"kbal","SourceHost":"KOKO","SourceIP":"-","DestinationHost":"KBSCCM","DestinationIP":"10.210.9.92","LogonType":"-","Reason":"Logon failed"}];
var userRiskExplorerData = [];
var UserRiskFailedByUserData = [{"TargetUser":"sccm_test","FailedCount":3,"LastSeenIso":"2026-04-03T10:25:24.5781226+03:00","LastSeenDisplay":"03/04/2026 10:25:24","TopSources":"KBSCCM"},{"TargetUser":"testuser_wrong","FailedCount":3,"LastSeenIso":"2026-04-03T10:20:49.1850254+03:00","LastSeenDisplay":"03/04/2026 10:20:49","TopSources":"KBDC01"},{"TargetUser":"kbal","FailedCount":3,"LastSeenIso":"2026-04-03T10:20:21.6505014+03:00","LastSeenDisplay":"03/04/2026 10:20:21","TopSources":"KOKO"}];
var UserRiskFailedBySourceData = [{"Source":"KBSCCM","FailedCount":3,"LastSeenIso":"2026-04-03T10:25:24.5781226+03:00","LastSeenDisplay":"03/04/2026 10:25:24","TopUsers":"sccm_test"},{"Source":"KBDC01","FailedCount":3,"LastSeenIso":"2026-04-03T10:20:49.1850254+03:00","LastSeenDisplay":"03/04/2026 10:20:49","TopUsers":"testuser_wrong"},{"Source":"KOKO","FailedCount":3,"LastSeenIso":"2026-04-03T10:20:21.6505014+03:00","LastSeenDisplay":"03/04/2026 10:20:21","TopUsers":"kbal"}];
var userRiskFailedUsersData = [];
var userRiskFailedSourcesData = [];
var userRiskDefaultPresetApplied = false;
var execScore = 56;
var execRating = 'Acceptable';
var execDomain = 'kuso.local';
var execDate = '2026-04-05 16:49:21';
var execPreviousDate = '2026-04-05 16:48:17';
var execPreviousScore = '56';
var execCritical = ;
var execHigh = ;
var execMedium = ;
var execLow = ;
var currentContainerId = 'pingCastleRisksContainer';
var currentRiskFocusMode = 'all';
var currentTrackingFilter = 'all';
var currentBaselineChangeFilter = 'all';
var remediationTrackingStore = {};
var changeApprovalGateStore = {};
var riskWatchlistStore = {};
var currentLanguage = 'en';
var domTextOriginalMap = new WeakMap();
var domAttrOriginalMap = new WeakMap();
var domTranslationObserver = null;
var isApplyingDomTranslation = false;

var domTextExactTr = {
    'Command Center': 'Komuta Merkezi',
    'AD Risk Mission Board': 'AD Risk G\u00f6rev Panosu',
    'Fast path: read current exposure, execute actions, then track closure status. Designed for daily operational rhythm.': 'H\u0131zl\u0131 ak\u0131\u015f: mevcut maruziyeti oku, aksiyon al, sonra kapan\u0131\u015f durumunu takip et. G\u00fcnl\u00fck operasyon ritmine g\u00f6re tasarland\u0131.',
    'Step 1': 'Ad\u0131m 1',
    'Step 2': 'Ad\u0131m 2',
    'Step 3': 'Ad\u0131m 3',
    'Read Risk Now': 'Anl\u0131k Riski Oku',
    'Execute Actions': 'Aksiyonlar\u0131 Uygula',
    'Track Closure': 'Kapan\u0131\u015f\u0131 Takip Et',
    'Quick Jump': 'H\u0131zl\u0131 Ge\u00e7i\u015f',
    'Risk Now': 'Anl\u0131k Risk',
    'Risk Model': 'Risk Modeli',
    'Findings': 'Bulgular',
    'Actions': 'Aksiyonlar',
    'Tracking': 'Takip',
    'Watchlist': '\u0130zleme Listesi',
    'Executive PDF': 'Y\u00f6netici \u00d6zeti PDF',
    'Remediation Checklist PDF': '\u0130yile\u015ftirme Kontrol Listesi PDF',
    'MITRE Navigator JSON': 'MITRE Navigator JSON',
    'Tracking JSON Export': 'Takip JSON D\u0131\u015fa Aktar',
    'Recommended Sequence': '\u00d6nerilen S\u0131ra',
    'Current: -/100': 'G\u00fcncel: -/100',
    'No trend data available yet.': 'Hen\u00fcz trend verisi yok.',
    'Recommendation': '\u00d6neri',
    'Category': 'Kategori',
    'Penalty Points': 'Ceza Puan\u0131',
    'Category Risk %': 'Kategori Risk %',
    'Matched Rules': 'E\u015fle\u015fen Kurallar',
    'Score Impact Simulation': 'Skor Etki Sim\u00fclasyonu',
    'Risk Contribution Decomposition': 'Risk Katk\u0131 Da\u011f\u0131l\u0131m\u0131',
    'Model how closing Findings can lower Risk score before remediation execution.': 'Bulgular kapat\u0131ld\u0131\u011f\u0131nda, iyile\u015ftirme uygulanmadan \u00f6nce risk skorunun nas\u0131l d\u00fc\u015fece\u011fini modelle.',
    'Shows which primary categories contribute most to the Current score.': 'Birincil kategorilerin g\u00fcncel skora en fazla katk\u0131y\u0131 nas\u0131l yapt\u0131\u011f\u0131n\u0131 g\u00f6sterir.',
    'Close Critical Findings:': 'Kritik Bulgular\u0131 Kapat:',
    'Close High Findings:': 'Y\u00fcksek Bulgular\u0131 Kapat:',
    'Close Medium Findings:': 'Orta Bulgular\u0131 Kapat:',
    'Projected Score:': 'Tahmini Skor:',
    'Improvement:': '\u0130yile\u015fme:',
    'Privileged Infrastructure': 'Ayr\u0131cal\u0131kl\u0131 Altyap\u0131',
    'Certificate Authority': 'Sertifika Otoritesi',
    'Privileged Accounts': 'Ayr\u0131cal\u0131kl\u0131 Hesaplar',
    'Anomalies': 'Anomaliler',
    'Hygiene': 'Temizleme',
    'Trusts': 'G\u00fcven \u0130li\u015fkileri',
    'Stale Objects': 'Eski Nesneler',
    'Group cannot be resolved or access is denied.': 'Grup \u00e7\u00f6z\u00fcmlenemedi veya eri\u015fim engellendi.',
    'Publishing certificate data can indirectly affect authentication hygiene. Group cannot be resolved or access is denied.': 'Sertifika verisi yay\u0131nlama, kimlik do\u011frulama hijyenini dolayl\u0131 olarak etkileyebilir. Grup \u00e7\u00f6z\u00fcmlenemedi veya eri\u015fim engellendi.',
    'DNS admins can influence name resolution and potentially abuse DC plugin loading paths.': 'DNS y\u00f6neticileri ad \u00e7\u00f6z\u00fcmlemeyi etkileyebilir ve DC eklenti y\u00fckleme yollar\u0131n\u0131 k\u00f6t\u00fcye kullanabilir.',
    'Domain-wide administrative rights should be tightly limited and controlled.': 'Etki alan\u0131 geneli y\u00f6netsel haklar s\u0131k\u0131 bi\u00e7imde s\u0131n\u0131rland\u0131r\u0131lmal\u0131 ve denetlenmelidir.',
    'Forest-wide administrative rights should remain minimal and break-glass only.': 'Orman geneli y\u00f6netsel haklar minimumda kalmal\u0131 ve yaln\u0131zca acil durum i\u00e7in kullan\u0131lmal\u0131d\u0131r.',
    'Key administration rights can affect account credentials and key material.': 'Anahtar y\u00f6netim haklar\u0131 hesap kimlik bilgilerini ve anahtar materyalini etkileyebilir.',
    'GPO creation rights can enable broad policy abuse if not constrained.': 'GPO olu\u015fturma haklar\u0131 s\u0131n\u0131rland\u0131r\u0131lmazsa geni\u015f \u00f6l\u00e7ekli ilke suistimaline yol a\u00e7abilir.',
    'Name': 'Ad',
    'Enabled': 'Etkin',
    'Password Never Expires': '\u015eifre S\u00fcresi Dolmaz',
    'Last Logon': 'Son Oturum A\u00e7ma',
    'Domain Admin': 'Domain Admin',
    'Schema Admin': 'Schema Admin',
    'Enterprise Admin': 'Enterprise Admin',
    'Hostname': 'Makine Ad\u0131',
    'OS': '\u0130\u015fletim Sistemi',
    'Status': 'Durum',
    'User': 'Kullan\u0131c\u0131',
    'Source Host': 'Kaynak Sunucu',
    'Source IP': 'Kaynak IP',
    'Destination Host': 'Hedef Sunucu',
    'Destination IP': 'Hedef IP',
    'Reason': 'Gerek\u00e7e',
    'Good': '\u0130yi',
    'Acceptable': 'Kabul Edilebilir',
    'Poor': 'Zay\u0131f',
    'Critical': 'Kritik',
    'High': 'Y\u00fcksek',
    'Medium': 'Orta',
    'Low': 'D\u00fc\u015f\u00fck',
    'Yes': 'Evet',
    'No': 'Hay\u0131r',
    'Never': 'Hi\u00e7'
};

var domTextRegexTr = [
    { re: /Immediate containment needed/g, to: 'Acil kapatma gerekli' },
    { re: /Prioritize in current sprint/g, to: 'Mevcut sprintte \u00f6nceliklendir' },
    { re: /Track and reduce baseline drift/g, to: 'Baseline sapmas\u0131n\u0131 izleyip azalt' },
    { re: /Observed count:/g, to: 'G\u00f6zlenen adet:' },
    { re: /Inventory in scope/g, to: 'Kapsamdaki envanter' },
    { re: /Recent logon timestamp/g, to: 'Yak\u0131n oturum a\u00e7ma zaman\u0131' }
];

var domTextLooseRegexTr = [
    { re: /\bRecommended\b/gi, to: '\u00d6nerilen' },
    { re: /\bOverview\b/gi, to: 'Genel Bak\u0131\u015f' },
    { re: /\bDashboard\b/gi, to: 'Pano' },
    { re: /\bMission Board\b/gi, to: 'G\u00f6rev Panosu' },
    { re: /\bRisk\b/gi, to: 'Risk' },
    { re: /\bRecommendation\b/gi, to: '\u00d6neri' },
    { re: /\bCategory\b/gi, to: 'Kategori' },
    { re: /\bPenalty Points\b/gi, to: 'Ceza Puan\u0131' },
    { re: /\bMatched Rules\b/gi, to: 'E\u015fle\u015fen Kurallar' },
    { re: /\bPrivileged\b/gi, to: 'Ayr\u0131cal\u0131kl\u0131' },
    { re: /\bInfrastructure\b/gi, to: 'Altyap\u0131' },
    { re: /\bAccounts\b/gi, to: 'Hesaplar' },
    { re: /\bTrusts\b/gi, to: 'G\u00fcven \u0130li\u015fkileri' },
    { re: /\bHygiene\b/gi, to: 'Temizleme' },
    { re: /\bStale\b/gi, to: 'Eski' },
    { re: /\bFindings\b/gi, to: 'Bulgular' },
    { re: /\bModel\b/gi, to: 'Model' },
    { re: /\bAction(s)?\b/gi, to: function(_, s){ return s ? 'Aksiyonlar' : 'Aksiyon'; } },
    { re: /\bTracking\b/gi, to: 'Takip' },
    { re: /\bWatchlist\b/gi, to: '\u0130zleme Listesi' },
    { re: /\bQuick Jump\b/gi, to: 'H\u0131zl\u0131 Ge\u00e7i\u015f' },
    { re: /\bCopy\b/gi, to: 'Kopyala' },
    { re: /\bPermalink\b/gi, to: 'Kal\u0131c\u0131 Ba\u011flant\u0131' },
    { re: /\bLink\b/gi, to: 'Ba\u011flant\u0131' },
    { re: /\bExecutive\b/gi, to: 'Y\u00f6netici' },
    { re: /\bRemediation\b/gi, to: '\u0130yile\u015ftirme' },
    { re: /\bChecklist\b/gi, to: 'Kontrol Listesi' },
    { re: /\bExport\b/gi, to: 'D\u0131\u015fa Aktar' },
    { re: /\bUsers\b/gi, to: 'Kullan\u0131c\u0131lar' },
    { re: /\bUser\b/gi, to: 'Kullan\u0131c\u0131' },
    { re: /\bGroups\b/gi, to: 'Gruplar' },
    { re: /\bGroup\b/gi, to: 'Grup' },
    { re: /\bSecurity\b/gi, to: 'G\u00fcvenlik' },
    { re: /\bSites\b/gi, to: 'Siteler' },
    { re: /\bSite\b/gi, to: 'Site' },
    { re: /\bTopology\b/gi, to: 'Topoloji' },
    { re: /\bInactive\b/gi, to: 'Pasif' },
    { re: /\bObjects\b/gi, to: 'Nesneler' },
    { re: /\bObject\b/gi, to: 'Nesne' },
    { re: /\bHealth\b/gi, to: 'Sa\u011fl\u0131k' },
    { re: /\bLocked Accounts\b/gi, to: 'Kilitli Hesaplar' },
    { re: /\bPassword Expiry\b/gi, to: '\u015eifre S\u00fcresi Dolumu' },
    { re: /\bSkipped\b/gi, to: 'Atlanan' },
    { re: /\bUnreachable\b/gi, to: 'Ula\u015f\u0131lamayan' },
    { re: /\bCurrent\b/gi, to: 'G\u00fcncel' },
    { re: /\brecords listed\b/gi, to: 'kay\u0131t listelendi' },
    { re: /\bTotal\b/gi, to: 'Toplam' },
    { re: /\bEnabled\b/gi, to: 'Etkin' },
    { re: /\bDisabled\b/gi, to: 'Devre D\u0131\u015f\u0131' },
    { re: /\bNever\b/gi, to: 'Hi\u00e7' },
    { re: /\bServer\b/gi, to: 'Sunucu' },
    { re: /\bClient\b/gi, to: '\u0130stemci' },
    { re: /\bLegacy\b/gi, to: 'Eski S\u00fcr\u00fcm' },
    { re: /\bUnknown\b/gi, to: 'Bilinmeyen' },
    { re: /\bHostname\b/gi, to: 'Makine Ad\u0131' },
    { re: /\bLast Logon\b/gi, to: 'Son Oturum A\u00e7ma' },
    { re: /\bStatus\b/gi, to: 'Durum' },
    { re: /\bReason\b/gi, to: 'Gerek\u00e7e' },
    { re: /\bGroup cannot be resolved or access is denied\.?/gi, to: 'Grup \u00e7\u00f6z\u00fcmlenemedi veya eri\u015fim engellendi.' }
];

var i18nStrings = {
    en: {
        'header.title': 'Active Directory Overview',
        'nav.copyPermalink': 'Copy Permalink',
        'nav.adRiskDashboard': 'AD Risk Dashboard',
        'nav.riskBaselineDiff': 'Risk Baseline Diff',
        'nav.userRiskLevel': 'AD User Risk Level',
        'nav.windowsOverview': 'Windows OS Overview',
        'nav.adUsersOverview': 'AD Users Overview',
        'nav.groupsSecurity': 'Groups & Security',
        'nav.adSitesTopology': 'AD Sites & Topology',
        'nav.inactiveObjects': 'Inactive Objects',
        'nav.dcHealthFsmo': 'DC Health & FSMO',
        'nav.exchangeUsers': 'Exchange/O365 Users',
        'nav.lockedAccounts': 'Locked Accounts',
        'nav.passwordExpiry': 'Password Expiry',
        'nav.skippedDcs': 'Skipped / Unreachable DCs',
        'risk.copyDashboardLink': 'Copy Dashboard Link',
        'risk.caLensTitle': 'CA Risk Lens',
        'risk.caLensMeta': 'Aggregates certificate service (AD CS/CA) risks in one place and guides closure priority.',
        'risk.quickJump': 'Quick Jump',
        'risk.quickRiskNow': 'Risk Now',
        'risk.quickRiskModel': 'Risk Model',
        'risk.quickFindings': 'Findings',
        'risk.quickActions': 'Actions',
        'risk.quickCA': 'CA',
        'risk.quickTracking': 'Tracking',
        'risk.quickWatchlist': 'Watchlist',
        'alert.permalinkCopied': 'Permalink copied to clipboard.',
        'alert.permalinkFallback': 'Permalink: '
    },
    tr: {
        'header.title': 'Active Directory Genel Bakış',
        'nav.copyPermalink': 'Kalıcı Bağlantıyı Kopyala',
        'nav.adRiskDashboard': 'AD Risk Panosu',
        'nav.riskBaselineDiff': 'Risk Baseline Farkı',
        'nav.userRiskLevel': 'AD Kullanıcı Risk Seviyesi',
        'nav.windowsOverview': 'Windows OS Genel Bakış',
        'nav.adUsersOverview': 'AD Kullanıcılar Genel Bakış',
        'nav.groupsSecurity': 'Gruplar ve Güvenlik',
        'nav.adSitesTopology': 'AD Site ve Topoloji',
        'nav.inactiveObjects': 'Pasif Nesneler',
        'nav.dcHealthFsmo': 'DC Sağlığı ve FSMO',
        'nav.exchangeUsers': 'Exchange/O365 Kullanıcıları',
        'nav.lockedAccounts': 'Kilitli Hesaplar',
        'nav.passwordExpiry': 'Şifre Süresi Dolumu',
        'nav.skippedDcs': 'Atlanan / Ulaşılamayan DC\'ler',
        'risk.copyDashboardLink': 'Pano Bağlantısını Kopyala',
        'risk.caLensTitle': 'CA Risk Lens',
        'risk.caLensMeta': 'Sertifika servisi (AD CS/CA) kaynakli riskleri tek yerde toplar ve kapanis onceligi verir.',
        'risk.quickJump': 'Hızlı Geçiş',
        'risk.quickRiskNow': 'Anlık Risk',
        'risk.quickRiskModel': 'Risk Modeli',
        'risk.quickFindings': 'Bulgular',
        'risk.quickActions': 'Aksiyonlar',
        'risk.quickCA': 'CA',
        'risk.quickTracking': 'Takip',
        'risk.quickWatchlist': 'İzleme Listesi',
        'alert.permalinkCopied': 'Kalıcı bağlantı panoya kopyalandı.',
        'alert.permalinkFallback': 'Kalıcı bağlantı: '
    }
};

function textFor(key, fallback){
    var dict = i18nStrings[currentLanguage] || i18nStrings.en;
    if (dict && Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
    return fallback || key;
}

function translateTextToTurkish(input){
    var text = String(input || '');
    if (!text) return text;

    var leading = text.match(/^\s*/);
    var trailing = text.match(/\s*$/);
    var prefix = leading ? leading[0] : '';
    var suffix = trailing ? trailing[0] : '';
    var core = text.trim();
    if (!core) return text;

    if (Object.prototype.hasOwnProperty.call(domTextExactTr, core)) {
        return prefix + domTextExactTr[core] + suffix;
    }

    core = core
        .replace(/^Disable\b/i, 'Devre dışı bırak')
        .replace(/^Enable\b/i, 'Etkinleştir')
        .replace(/^Enforce\b/i, 'Zorunlu kıl')
        .replace(/^Review\b/i, 'Gözden geçir')
        .replace(/^Rotate\b/i, 'Değiştir')
        .replace(/^Set\b/i, 'Ayarla')
        .replace(/^Remove\b/i, 'Kaldır')
        .replace(/^Restrict\b/i, 'Sınırla')
        .replace(/^Use\b/i, 'Kullan')
        .replace(/^Track\b/i, 'Takip et')
        .replace(/^Separate\b/i, 'Ayrıştır')
        .replace(/^Close\b/i, 'Kapat')
        .replace(/^Clean\b/i, 'Temizle')
        .replace(/^Harden\b/i, 'Sıkılaştır')
        .replace(/^Migrate\b/i, 'Taşı')
        .replace(/^Validate\b/i, 'Doğrula')
        .replace(/^Implement\b/i, 'Uygula')
        .replace(/^Adopt\b/i, 'Benimse')
        .replace(/^Configure\b/i, 'Yapılandır');

    for (var i = 0; i < domTextRegexTr.length; i++) {
        var rule = domTextRegexTr[i];
        if (rule.re.test(core)) {
            core = core.replace(rule.re, rule.to);
        }
    }

    for (var j = 0; j < domTextLooseRegexTr.length; j++) {
        var looseRule = domTextLooseRegexTr[j];
        core = core.replace(looseRule.re, looseRule.to);
    }

    return prefix + core + suffix;
}

function applyDomAttributeTranslation(lang){
    var attrs = ['title', 'aria-label', 'placeholder'];
    var selector = '[title],[aria-label],[placeholder],button[value],input[type="button"][value],input[type="submit"][value]';
    var nodes = document.querySelectorAll(selector);

    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var originalAttrs = domAttrOriginalMap.get(node);
        if (!originalAttrs) {
            originalAttrs = {};
            for (var a = 0; a < attrs.length; a++) {
                if (node.hasAttribute(attrs[a])) {
                    originalAttrs[attrs[a]] = node.getAttribute(attrs[a]);
                }
            }
            if (node.hasAttribute('value')) {
                originalAttrs.value = node.getAttribute('value');
            }
            domAttrOriginalMap.set(node, originalAttrs);
        }

        if (lang === 'tr') {
            for (var b = 0; b < attrs.length; b++) {
                var attr = attrs[b];
                if (Object.prototype.hasOwnProperty.call(originalAttrs, attr)) {
                    node.setAttribute(attr, translateTextToTurkish(originalAttrs[attr]));
                }
            }
            if (Object.prototype.hasOwnProperty.call(originalAttrs, 'value')) {
                node.setAttribute('value', translateTextToTurkish(originalAttrs.value));
            }
        } else {
            for (var c = 0; c < attrs.length; c++) {
                var attrName = attrs[c];
                if (Object.prototype.hasOwnProperty.call(originalAttrs, attrName)) {
                    node.setAttribute(attrName, originalAttrs[attrName]);
                }
            }
            if (Object.prototype.hasOwnProperty.call(originalAttrs, 'value')) {
                node.setAttribute('value', originalAttrs.value);
            }
        }
    }
}

function applyDomTranslation(lang){
    if (isApplyingDomTranslation) return;
    isApplyingDomTranslation = true;

    var root = document.body;
    if (!root) {
        isApplyingDomTranslation = false;
        return;
    }

    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
        acceptNode: function(node){
            if (!node || !node.parentElement) return NodeFilter.FILTER_REJECT;
            var tag = node.parentElement.tagName;
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') return NodeFilter.FILTER_REJECT;
            if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
            return NodeFilter.FILTER_ACCEPT;
        }
    });

    var textNodes = [];
    var current = walker.nextNode();
    while (current) {
        textNodes.push(current);
        current = walker.nextNode();
    }

    for (var i = 0; i < textNodes.length; i++) {
        var textNode = textNodes[i];
        if (!domTextOriginalMap.has(textNode)) {
            domTextOriginalMap.set(textNode, textNode.nodeValue);
        }

        var original = domTextOriginalMap.get(textNode);
        if (lang === 'tr') {
            textNode.nodeValue = translateTextToTurkish(original);
        } else {
            textNode.nodeValue = original;
        }
    }

    applyDomAttributeTranslation(lang);
    isApplyingDomTranslation = false;
}

function startDomTranslationObserver(){
    if (domTranslationObserver || !window.MutationObserver || !document.body) return;
    domTranslationObserver = new MutationObserver(function(){
        if (currentLanguage === 'tr') {
            applyDomTranslation('tr');
        }
    });

    domTranslationObserver.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
        attributes: true,
        attributeFilter: ['title', 'aria-label', 'placeholder', 'value']
    });
}

function stopDomTranslationObserver(){
    if (!domTranslationObserver) return;
    domTranslationObserver.disconnect();
    domTranslationObserver = null;
}

function applyLanguage(lang){
    currentLanguage = (lang === 'tr') ? 'tr' : 'en';
    document.title = (currentLanguage === 'tr') ? 'Active Directory Genel Bakış' : 'Active Directory Overview';
    var nodes = document.querySelectorAll('[data-i18n-key]');
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var key = node.getAttribute('data-i18n-key');
        if (!key) continue;
        node.textContent = textFor(key, node.textContent);
    }

    var langToggle = document.getElementById('langToggleBtn');
    if (langToggle) {
        langToggle.textContent = (currentLanguage === 'tr') ? 'EN' : 'TR';
        langToggle.title = (currentLanguage === 'tr') ? 'Switch to English' : 'Türkçeye geç';
    }

    applyDomTranslation(currentLanguage);
    if (currentLanguage === 'tr') startDomTranslationObserver();
    else stopDomTranslationObserver();

    if (typeof renderCaRiskLens === 'function') renderCaRiskLens();
    if (typeof renderOUTierAdvisorShell === 'function') renderOUTierAdvisorShell();

    try { localStorage.setItem('adcheck-lang', currentLanguage); } catch (e) {}
}

function toggleLanguage(){
    applyLanguage(currentLanguage === 'tr' ? 'en' : 'tr');
    updateHashFromState();
}

var riskCategoryThresholdMap = {
    'Stale Objects': 80,
    'Privileged Accounts': 100,
    'Privileged Infrastructure': 120,
    'Certificate Authority': 80,
    'Trusts': 60,
    'Anomalies': 80,
    'Hygiene': 60
};
var riskCategoryWeightMap = {
    'Stale Objects': 20,
    'Privileged Accounts': 20,
    'Privileged Infrastructure': 20,
    'Trusts': 20,
    'Anomalies': 20
};
var riskSeverityWeightMap = { Critical: 25, High: 10, Medium: 4, Low: 1 };

function safeArray(input){
    return Array.isArray(input) ? input : (input ? [input] : []);
}

function scrollRiskStoryboard(anchorId){
    var node = document.getElementById(anchorId);
    if (!node) return;
    try {
        node.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
        node.scrollIntoView(true);
    }
}

function escapeHtml(text){
    return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function safeBase64Encode(str){
    try {
        return btoa(unescape(encodeURIComponent(String(str || ''))));
    } catch (e) {
        return '';
    }
}

function safeBase64Decode(str){
    try {
        return decodeURIComponent(escape(atob(String(str || ''))));
    } catch (e) {
        return '';
    }
}

function getGroupMembers(){
    if (!GroupMembers && window.__adcheckGroupMembers) GroupMembers = window.__adcheckGroupMembers;
    return GroupMembers;
}

function getObjectRiskDetails(){
    if (!ObjectRiskDetails && window.__adcheckObjectRiskDetails) ObjectRiskDetails = window.__adcheckObjectRiskDetails;
    return ObjectRiskDetails;
}

function loadSidecarScript(src, onDone){
    var existing = document.querySelector('script[data-sidecar-src="' + src + '"]');
    if (existing && existing.getAttribute('data-loaded') === '1') {
        if (typeof onDone === 'function') onDone();
        return;
    }

    if (existing && existing.getAttribute('data-loading') === '1') {
        existing.addEventListener('load', function(){ if (typeof onDone === 'function') onDone(); });
        return;
    }

    var script = existing || document.createElement('script');
    script.src = src;
    script.async = true;
    script.setAttribute('data-sidecar-src', src);
    script.setAttribute('data-loading', '1');
    script.onload = function(){
        script.setAttribute('data-loaded', '1');
        script.setAttribute('data-loading', '0');
        if (typeof onDone === 'function') onDone();
    };
    script.onerror = function(){
        script.setAttribute('data-loaded', '0');
        script.setAttribute('data-loading', '0');
        if (typeof onDone === 'function') onDone();
    };
    if (!existing) document.head.appendChild(script);
}

function ensureGroupMembersLoaded(onDone){
    if (getGroupMembers()) {
        if (typeof onDone === 'function') onDone();
        return;
    }
    loadSidecarScript('tools/groupMembersData.js', function(){
        if (window.__adcheckGroupMembers) GroupMembers = window.__adcheckGroupMembers;
        if (typeof onDone === 'function') onDone();
    });
}

function ensureObjectRiskDetailsLoaded(onDone){
    if (getObjectRiskDetails()) {
        if (typeof onDone === 'function') onDone();
        return;
    }
    loadSidecarScript('tools/objectRiskData.js', function(){
        if (window.__adcheckObjectRiskDetails) ObjectRiskDetails = window.__adcheckObjectRiskDetails;
        if (typeof onDone === 'function') onDone();
    });
}

function getRemediationBaselineMap(){
    if (!window.__remediationBaselineMap) {
        window.__remediationBaselineMap = {};
        safeArray(remediationBaselineStates).forEach(function(item){
            if (!item || !item.Key) return;
            window.__remediationBaselineMap[item.Key] = {
                status: String(item.Status || 'open').toLowerCase(),
                note: String(item.Note || ''),
                updatedAt: String(item.UpdatedAt || '')
            };
        });
    }
    return window.__remediationBaselineMap;
}

function normalizeRemediationStatus(status){
    var s = String(status || 'open').toLowerCase();
    if (s === 'fix' || s === 'fixed') s = 'fixing';
    if (s !== 'open' && s !== 'fixing' && s !== 'accepted' && s !== 'exception') s = 'open';
    return s;
}

function readRemediationStorageEntry(key){
    try {
        var raw = localStorage.getItem('adcheck-remediation-' + key);
        if (raw) {
            var parsed = JSON.parse(raw);
            return {
                status: normalizeRemediationStatus(parsed.status || 'open'),
                note: String(parsed.note || ''),
                updatedAt: String(parsed.updatedAt || '')
            };
        }
    } catch (e) {}
    return null;
}

function getTrackingEntry(key){
    if (!key) return { status: 'open', note: '', updatedAt: '' };
    if (remediationTrackingStore && remediationTrackingStore[key]) {
        return remediationTrackingStore[key];
    }
    var localEntry = readRemediationStorageEntry(key);
    if (localEntry) return localEntry;
    var baselineMap = getRemediationBaselineMap();
    if (baselineMap[key]) return baselineMap[key];
    return { status: 'open', note: '', updatedAt: '' };
}

function setTrackingEntry(key, entry){
    if (!key) return;
    remediationTrackingStore[key] = {
        status: normalizeRemediationStatus(entry && entry.status),
        note: String((entry && entry.note) || ''),
        updatedAt: String((entry && entry.updatedAt) || '')
    };
}

function persistTrackingEntry(key, entry){
    var normalized = {
        status: normalizeRemediationStatus(entry && entry.status),
        note: String((entry && entry.note) || ''),
        updatedAt: String((entry && entry.updatedAt) || new Date().toISOString())
    };
    setTrackingEntry(key, normalized);
    try { localStorage.setItem('adcheck-remediation-' + key, JSON.stringify(normalized)); } catch (e) {}
    try { localStorage.setItem('adcheck-remediation-tracking', JSON.stringify(remediationTrackingStore)); } catch (e) {}
    return normalized;
}

function buildTrackingControls(entry){
    var status = normalizeRemediationStatus(entry && entry.status);
    var note = String((entry && entry.note) || '');
    var updatedAt = String((entry && entry.updatedAt) || '');
    var meta = remediationStatusMeta(status);
    var updatedText = updatedAt ? ('<span class="remediation-updated-at" style="font-size:10px;color:#5b7087;">Updated: ' + escapeHtml(updatedAt) + '</span>') : '';
    return ''
        + '<div style="display:flex;flex-direction:column;gap:6px;min-width:260px;">'
        + '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        + '<select class="risk-action-btn remediation-status-select" style="padding:4px 8px;font-size:11px;min-width:110px;" onchange="setFindingStatus(this)">'
        + '<option value="open"' + (status === 'open' ? ' selected' : '') + '>Open</option>'
        + '<option value="fixing"' + (status === 'fixing' ? ' selected' : '') + '>Fixing</option>'
        + '<option value="accepted"' + (status === 'accepted' ? ' selected' : '') + '>Accepted</option>'
        + '<option value="exception"' + (status === 'exception' ? ' selected' : '') + '>Exception</option>'
        + '</select>'
        + '<span class="' + meta.cls + ' remediation-status-pill-live" data-remediation-pill="1">' + meta.label + '</span>'
        + '</div>'
        + '<input type="text" class="remediation-note-input" style="padding:5px 8px;border:1px solid #b7cce2;border-radius:8px;font-size:11px;width:100%;box-sizing:border-box;" placeholder="Note" value="' + escapeHtml(note) + '" oninput="setFindingNote(this)">'
        + '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        + '<button class="risk-action-btn" style="padding:5px 10px;font-size:11px;" onclick="saveRemediationRow(this)">Kaydet</button>'
        + '<span class="remediation-save-status" data-remediation-save-status="1" style="font-size:10px;color:#52708f;display:none;">Kaydedildi ✓</span>'
        + updatedText
        + '</div>'
        + '</div>';
}

function updateTrackingRowUI(row, entry){
    if (!row || !row.cells || row.cells.length < 7) return;
    var statusCell = row.cells[6];
    if (!statusCell) return;
    statusCell.innerHTML = buildTrackingControls(entry);
}

function updateHashFromState(){
    var state = {
        c: currentContainerId || 'pingCastleRisksContainer',
        rf: currentRiskFocusMode || 'all',
        tf: currentTrackingFilter || 'all',
        dm: document.body.classList.contains('dark-mode') ? 1 : 0,
        lg: currentLanguage || 'en'
    };
    var encoded = safeBase64Encode(JSON.stringify(state));
    if (encoded) window.location.hash = encoded;
}

function readHashState(){
    var h = (window.location.hash || '').replace(/^#/, '');
    if (!h) return null;
    var text = safeBase64Decode(h);
    if (!text) return null;
    try {
        return JSON.parse(text);
    } catch (e) {
        return null;
    }
}

function applyDarkMode(enabled){
    if (enabled) document.body.classList.add('dark-mode');
    else document.body.classList.remove('dark-mode');
    try { localStorage.setItem('adcheck-dark-mode', enabled ? '1' : '0'); } catch(e){}
}

function toggleDarkMode(){
    var enabled = !document.body.classList.contains('dark-mode');
    applyDarkMode(enabled);
    updateHashFromState();
}

function copyPermalinkState(){
    updateHashFromState();
    var url = window.location.href;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function(){
            alert(textFor('alert.permalinkCopied', 'Permalink copied to clipboard.'));
        }).catch(function(){
            alert(textFor('alert.permalinkFallback', 'Permalink: ') + url);
        });
    } else {
        alert(textFor('alert.permalinkFallback', 'Permalink: ') + url);
    }
}

function drawRiskTrendSparkline(){
    var svg = document.getElementById('riskTrendSparkline');
    var currentBadge = document.getElementById('riskTrendCurrentBadge');
    if (!svg) return;
    var rows = safeArray(riskTrendSeries).slice(-24);
    if (!rows.length) {
        if (currentBadge) currentBadge.innerText = 'Current: -/100';
        svg.innerHTML = '<text x="12" y="56" fill="#5a6f84" font-size="12">No trend data available yet.</text>';
        return;
    }

    var w = 640, h = 120, padX = 18, padY = 20;
    var scores = rows.map(function(r){
        var v = parseFloat(r.DomainRiskScore);
        if (isNaN(v)) v = 0;
        return Math.max(0, Math.min(100, v));
    });

    var pathParts = [];
    for (var i = 0; i < scores.length; i++) {
        var x = padX + ((w - (padX * 2)) * (scores.length === 1 ? 0.5 : (i / (scores.length - 1))));
        var y = (h - padY) - ((h - (padY * 2)) * (scores[i] / 100));
        pathParts.push((i === 0 ? 'M' : 'L') + x.toFixed(2) + ' ' + y.toFixed(2));
    }

    var grid = '';
    [0,25,50,75,100].forEach(function(v){
        var gy = (h - padY) - ((h - (padY * 2)) * (v / 100));
        grid += '<line class="risk-trend-axis" x1="' + padX + '" y1="' + gy.toFixed(2) + '" x2="' + (w-padX) + '" y2="' + gy.toFixed(2) + '" />';
    });

    var points = '';
    scores.forEach(function(s, i){
        var x = padX + ((w - (padX * 2)) * (scores.length === 1 ? 0.5 : (i / (scores.length - 1))));
        var y = (h - padY) - ((h - (padY * 2)) * (s / 100));
        var cls = (i === scores.length - 1) ? 'risk-trend-point risk-trend-last' : 'risk-trend-point';
        points += '<circle class="' + cls + '" cx="' + x.toFixed(2) + '" cy="' + y.toFixed(2) + '" r="3.4" />';
    });

    var firstLabel = rows[0].GeneratedAt || '-';
    var lastLabel = rows[rows.length - 1].GeneratedAt || '-';
    var lastScore = scores[scores.length - 1];
    if (currentBadge) currentBadge.innerText = 'Current: ' + lastScore.toFixed(0) + '/100';

    svg.innerHTML =
        grid +
        '<path class="risk-trend-line" d="' + pathParts.join(' ') + '"></path>' +
        points +
        '<text x="' + padX + '" y="114" fill="#5a6f84" font-size="11">' + String(firstLabel).replace(/</g,'&lt;') + '</text>' +
        '<text x="' + (w - padX) + '" y="114" fill="#5a6f84" font-size="11" text-anchor="end">' + String(lastLabel).replace(/</g,'&lt;') + '</text>';
}

function buildAttackChainGraph(){
    var graphNode = document.getElementById('attackChainGraph');
    var whyList = document.getElementById('attackChainWhyList');
    if (!graphNode) return;

    var scenarios = safeArray(attackChainScenarios);
    if (!scenarios.length) {
        graphNode.innerHTML = '<div class="attack-scenario-empty">Bilinen saldiri zinciri tespit edilmedi</div>';
        if (whyList) whyList.innerHTML = '<li>No matched attack-chain scenario based on active finding combinations.</li>';
        return;
    }

    var cardsHtml = scenarios.map(function(s, idx){
        var risk = String((s && s.Risk) || '').toLowerCase();
        var border = (risk === 'critical') ? '#dc2626' : '#d97706';
        var bg = (risk === 'critical') ? 'rgba(220,38,38,.05)' : 'rgba(217,119,6,.07)';
        var steps = safeArray((s && s.Steps) || []).map(function(step){ return escapeHtml(String(step || '-')); }).join(' <span style="color:#64748b">&rarr;</span> ');
        var evidence = safeArray((s && s.Evidence) || []).map(function(ev){ return escapeHtml(String(ev || '-')); });
        var evidenceLine = evidence.length ? evidence.join(', ') : '-';
        return ''
            + '<button type="button" class="attack-scenario-card" onclick="showAttackScenarioDetail(' + idx + ')"'
            + ' style="width:100%;text-align:left;border:1px solid ' + border + ';background:' + bg + ';border-radius:10px;padding:10px 12px;margin-bottom:8px;cursor:pointer">'
            + '<div style="display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:6px">'
            + '<span style="font-weight:800;color:#183b5b">' + escapeHtml(String((s && s.ScenarioName) || 'Scenario')) + '</span>'
            + '<span style="font-size:11px;padding:2px 8px;border-radius:999px;background:' + border + ';color:#fff;font-weight:700">' + escapeHtml(String((s && s.Risk) || '-')) + '</span>'
            + '</div>'
            + '<div style="font-size:12px;color:#2f4963;line-height:1.4">' + steps + '</div>'
            + '<div style="font-size:11px;color:#465e75;margin-top:6px"><b>Evidence:</b> ' + evidenceLine + '</div>'
            + '</button>';
    }).join('');

    graphNode.innerHTML = cardsHtml;
    if (whyList) {
        whyList.innerHTML = scenarios.map(function(s){
            return '<li><b>' + escapeHtml(String((s && s.ScenarioName) || 'Scenario')) + ':</b> ' + escapeHtml(String((s && s.Description) || '')) + '</li>';
        }).join('');
    }
}

function showAttackScenarioDetail(index){
    var scenario = safeArray(attackChainScenarios)[index];
    if (!scenario) return;
    var title = 'Attack Scenario: ' + String(scenario.ScenarioName || 'Scenario');
    var steps = safeArray(scenario.Steps).join(' -> ');
    var evidence = safeArray(scenario.Evidence).join(', ');
    var body = 'Risk: ' + String(scenario.Risk || '-') + '\n\nSteps:\n' + steps + '\n\nEvidence:\n' + (evidence || '-') + '\n\n' + String(scenario.Description || '');
    if (typeof showModal === 'function') {
        try { showModal(title, body); return; } catch (e) {}
    }
    alert(title + '\n\n' + body);
}

function renderMitreHeatmap(){
    var host = document.getElementById('mitreHeatGrid');
    if (!host) return;
    var rows = safeArray(mitreRows);
    if (!rows.length) {
        host.innerHTML = '<div class="mitre-cell"><h4>No mapped finding</h4><p>Run with findings to populate ATT&CK coverage.</p></div>';
        return;
    }

    var map = {};
    rows.forEach(function(r){
        safeArray(r.Tactics).forEach(function(t){
            if (!map[t]) map[t] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            var s = String(r.Severity || 'Low');
            if (!map[t][s]) map[t][s] = 0;
            map[t][s] += 1;
        });
    });

    var tactics = Object.keys(map).sort();
    var html = '';
    tactics.forEach(function(t){
        var m = map[t];
        var severityClass = 'mitre-cell-medium';
        if ((m.Critical || 0) > 0) severityClass = 'mitre-cell-critical';
        else if ((m.High || 0) > 0) severityClass = 'mitre-cell-high';
        html += '<div class="mitre-cell ' + severityClass + '">'
            + '<h4>' + t.replace(/</g,'&lt;') + '</h4>'
            + '<p>C:' + (m.Critical || 0) + ' | H:' + (m.High || 0) + ' | M:' + (m.Medium || 0) + ' | L:' + (m.Low || 0) + '</p>'
            + '</div>';
    });
    host.innerHTML = html;
}

function renderThreatPriorityQueue(){
    var host = document.getElementById('threatPriorityBody');
    if (!host) return;
    var rows = safeArray(threatPriorityRows);
    if (!rows.length) {
        host.innerHTML = '<div class="threat-priority-note">Tehdit oncelik verisi bulunamadi.</div>';
        return;
    }

    var topRows = rows.slice(0, 15);
    var html = '<table class="threat-priority-table"><tr><th>Oncelik</th><th>Technique</th><th>Rule</th><th>Kategori</th><th>Tactics</th></tr>';
    topRows.forEach(function(r){
        html += '<tr>'
            + '<td>' + escapeHtml(String(r.PriorityScore || 0)) + '</td>'
            + '<td>' + escapeHtml(String(r.Technique || '-')) + '</td>'
            + '<td>' + escapeHtml(String(r.Rule || '-')) + '</td>'
            + '<td>' + escapeHtml(String(r.Category || '-')) + '</td>'
            + '<td>' + escapeHtml(String(r.Tactics || '-')) + '</td>'
            + '</tr>';
    });
    html += '</table>';
    host.innerHTML = html;
}

function renderCaRiskLens(){
    var host = document.getElementById('caRiskLensBody');
    if (!host) return;
    var rows = safeArray(caRiskRows);
    function L(en, tr){ return currentLanguage === 'tr' ? tr : en; }
    if (!rows.length) {
        host.innerHTML = ''
            + '<div class="ca-risk-meta">' + escapeHtml(L('No active AD CS/CA risk detected.', 'Aktif AD CS/CA riski tespit edilmedi.')) + '</div>'
            + '<ul class="ca-risk-checklist">'
            + '<li>' + escapeHtml(L('Keep template ACL change auditing enabled.', 'Template ACL degisiklik denetimini acik tutun.')) + '</li>'
            + '<li>' + escapeHtml(L('Review published CA templates monthly.', 'Yayinda olan CA template listesini aylik gozden gecirin.')) + '</li>'
            + '<li>' + escapeHtml(L('Compare CA findings with trend in the next report run.', 'Bir sonraki raporda CA bulgularini trend ile karsilastirin.')) + '</li>'
            + '</ul>';
        return;
    }

    var critical = rows.filter(function(r){ return String(r.Severity || '').toLowerCase() === 'critical'; }).length;
    var high = rows.filter(function(r){ return String(r.Severity || '').toLowerCase() === 'high'; }).length;
    var top = rows.slice(0, 10);

    function getCaRiskGuidance(row){
        var rule = String((row && row.Rule) || '').toLowerCase();
        var recommendation = String((row && row.Recommendation) || '');

        if (rule.indexOf('esc1') >= 0 || rule.indexOf('enrollee') >= 0 || rule.indexOf('subject') >= 0) {
            return {
                why: L('User-controlled Subject/SAN fields can enable certificate-based privilege escalation.', 'Kullanici kontrollu subject/SAN alanlari, sertifika ile yetki yukselmesine yol acabilir.'),
                verify: L('Validate Enrollee supplies subject with authentication EKU combination in template settings.', 'Template ayarlarinda Enrollee supplies subject ve auth EKU kombinasyonunu dogrula.'),
                action: L('Disable subject supply for this template, narrow enrollment scope, and keep only required EKUs.', 'Bu template icin subject supply ozelligini kapat, enrollment kapsamini daralt ve sadece gerekli EKU birak.'),
                eta: L('24-48 hours', '24-48 saat')
            };
        }
        if (rule.indexOf('esc4') >= 0 || rule.indexOf('acl') >= 0 || rule.indexOf('owner') >= 0 || rule.indexOf('rights') >= 0) {
            return {
                why: L('Broad write rights can allow template manipulation for certificate-based attacks.', 'Genis yazma haklari, template manipule edilerek sertifika tabanli saldiriya imkan tanir.'),
                verify: L('Check WriteDacl/WriteOwner/GenericAll rights on template nTSecurityDescriptor.', 'Template nTSecurityDescriptor uzerinde WriteDacl/WriteOwner/GenericAll yetkilerini kontrol et.'),
                action: L('Remove write rights from broad groups such as Domain Users/Authenticated Users and delegate only to PKI admins.', 'Domain Users/Authenticated Users benzeri genis gruplarin yazma haklarini kaldir ve PKI admin grubuna delege et.'),
                eta: L('Same day', 'Ayni gun')
            };
        }
        if (rule.indexOf('ad cs') >= 0 || rule.indexOf('certificate') >= 0 || rule.indexOf('template') >= 0 || rule.indexOf('pki') >= 0) {
            return {
                why: L('Weak PKI controls can impact authentication trust chain and increase lateral movement risk.', 'PKI tarafindaki zayif kontroller kimlik dogrulama zincirini etkileyerek lateral movement riskini artirir.'),
                verify: L('Compare template publish state, enrollment permissions, and EKU set against operational need.', 'Template yayin durumu, enrollment izinleri ve EKU setini operasyonel ihtiyacla karsilastir.'),
                action: recommendation || L('Narrow high-risk templates and permissions; remove unnecessary published templates.', 'Yuksek riskli template ve izinleri daralt; gereksiz publish edilen template leri kaldir.'),
                eta: L('72 hours', '72 saat')
            };
        }
        return {
            why: L('CA-related finding is a risk signal and may indirectly impact identity security.', 'CA baglantili bulgu risk sinyalidir ve kimlik guvenligini dolayli etkileyebilir.'),
            verify: L('Validate ACL and publish settings on the related template/CA object.', 'Ilgili template/CA nesnesinin ACL ve yayin ayarlarini dogrula.'),
            action: recommendation || L('Validate with technical team and open a change plan.', 'Bulguyu teknik ekip ile dogrulayip degisiklik plani ac.'),
            eta: L('Planned window', 'Planlanan pencere')
        };
    }

    var html = '';
    html += '<div class="ca-risk-kpi">';
    html += '<div class="section-stat-card"><div class="section-stat-label">' + escapeHtml(L('Total CA Risk', 'CA Toplam Risk')) + '</div><div class="section-stat-value">' + rows.length + '</div><div class="section-stat-note">' + escapeHtml(L('AD CS/certificate related', 'AD CS/sertifika baglantili')) + '</div></div>';
    html += '<div class="section-stat-card"><div class="section-stat-label">Critical</div><div class="section-stat-value">' + critical + '</div><div class="section-stat-note">' + escapeHtml(L('Immediate closure', 'Acil kapanis')) + '</div></div>';
    html += '<div class="section-stat-card"><div class="section-stat-label">High</div><div class="section-stat-value">' + high + '</div><div class="section-stat-note">' + escapeHtml(L('Prioritize in this sprint', 'Bu sprintte ele alin')) + '</div></div>';
    html += '</div>';
    html += '<ul class="ca-risk-checklist">';
    html += '<li>' + escapeHtml(L('1) Open a change record first for Critical/High CA findings.', '1) Once Critical/High CA bulgularina degisiklik kaydi ac.')) + '</li>';
    html += '<li>' + escapeHtml(L('2) Complete validation step and attach evidence URL for each finding.', '2) Her bulgu icin dogrulama adimini tamamla ve kanit URL si ekle.')) + '</li>';
    html += '<li>' + escapeHtml(L('3) Re-run report after closure and validate downward trend.', '3) Kapatma sonrasi raporu tekrar calistirip azalis trendini dogrula.')) + '</li>';
    html += '</ul>';
    html += '<div class="table-wrapper"><table class="user-table"><tr><th>Severity</th><th>Rule</th><th>' + escapeHtml(L('Why Risk', 'Neden Risk')) + '</th><th>' + escapeHtml(L('Action Required', 'Ne Yapilmali')) + '</th><th>' + escapeHtml(L('Target Time', 'Hedef Sure')) + '</th></tr>';
    top.forEach(function(r){
        var g = getCaRiskGuidance(r);
        var sev = escapeHtml(String(r.Severity || '-'));
        html += '<tr>'
            + '<td><span class="ca-risk-badge">' + sev + '</span></td>'
            + '<td>' + escapeHtml(String(r.Rule || '-')) + '</td>'
            + '<td><div class="ca-risk-why">' + escapeHtml(g.why) + '<br><strong>' + escapeHtml(L('Validation:', 'Dogrulama:')) + '</strong> ' + escapeHtml(g.verify) + '</div></td>'
            + '<td><div class="ca-risk-action">' + escapeHtml(g.action) + '</div></td>'
            + '<td>' + escapeHtml(g.eta) + '</td>'
            + '</tr>';
    });
    html += '</table></div>';
    host.innerHTML = html;
}

function exportMitreNavigatorJson(){
    var rows = safeArray(mitreRows);
    var layer = {
        version: '4.5',
        name: 'AD Risk ATT&CK Mapping',
        domain: 'enterprise-attack',
        description: 'Generated from AD Health Check findings',
        techniques: []
    };

    rows.forEach(function(r){
        safeArray(r.Techniques).forEach(function(tid){
            var score = (String(r.Severity || '').toLowerCase() === 'critical') ? 100 :
                        (String(r.Severity || '').toLowerCase() === 'high') ? 80 :
                        (String(r.Severity || '').toLowerCase() === 'medium') ? 55 : 35;
            layer.techniques.push({ techniqueID: tid.split(' ')[0], score: score, comment: (r.Rule || '') });
        });
    });

    var blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mitre_attack_navigator_layer.json';
    a.click();
    URL.revokeObjectURL(a.href);
}

function loadRemediationTracking(){
    try {
        var raw = localStorage.getItem('adcheck-remediation-tracking');
        remediationTrackingStore = raw ? JSON.parse(raw) : {};
    } catch (e) {
        remediationTrackingStore = {};
    }
}

function getTrackingEntry(key){
    if (!key) return { status: 'open', note: '', updatedAt: '' };
    if (remediationTrackingStore && remediationTrackingStore[key]) {
        return remediationTrackingStore[key];
    }
    var localEntry = readRemediationStorageEntry(key);
    if (localEntry) {
        remediationTrackingStore[key] = localEntry;
        return localEntry;
    }
    var baselineMap = getRemediationBaselineMap();
    if (baselineMap[key]) {
        remediationTrackingStore[key] = baselineMap[key];
        return baselineMap[key];
    }
    return { status: 'open', note: '', updatedAt: '' };
}

function setTrackingEntry(key, entry){
    remediationTrackingStore[key] = {
        status: normalizeRemediationStatus(entry && entry.status),
        note: String((entry && entry.note) || ''),
        updatedAt: String((entry && entry.updatedAt) || '')
    };
}

function saveRemediationTracking(){
    try { localStorage.setItem('adcheck-remediation-tracking', JSON.stringify(remediationTrackingStore)); } catch(e){}
}

function loadChangeApprovalGate(){
    try {
        var raw = localStorage.getItem('adcheck-change-approval');
        changeApprovalGateStore = raw ? JSON.parse(raw) : {};
    } catch (e) {
        changeApprovalGateStore = {};
    }
}

function saveChangeApprovalGate(){
    try { localStorage.setItem('adcheck-change-approval', JSON.stringify(changeApprovalGateStore || {})); } catch(e){}
}

function getChangeApprovalSnapshot(){
    return {
        ticket: String((changeApprovalGateStore && changeApprovalGateStore.ticket) || ''),
        owner: String((changeApprovalGateStore && changeApprovalGateStore.owner) || ''),
        window: String((changeApprovalGateStore && changeApprovalGateStore.window) || ''),
        rollback: String((changeApprovalGateStore && changeApprovalGateStore.rollback) || ''),
        checks: {
            impact: !!(changeApprovalGateStore && changeApprovalGateStore.impact),
            testPlan: !!(changeApprovalGateStore && changeApprovalGateStore.testPlan),
            backout: !!(changeApprovalGateStore && changeApprovalGateStore.backout),
            evidence: !!(changeApprovalGateStore && changeApprovalGateStore.evidence)
        }
    };
}

function updateApprovalGateStatus(){
    var statusNode = document.getElementById('approvalGateStatus');
    if (!statusNode) return;
    var s = getChangeApprovalSnapshot();
    var checklistOk = s.checks.impact && s.checks.testPlan && s.checks.backout && s.checks.evidence;
    var fieldsOk = !!(s.ticket && s.owner && s.window && s.rollback);
    if (checklistOk && fieldsOk) {
        statusNode.innerHTML = '<span class="remediation-status-pill remediation-status-fix">Onay Hazir</span> Degisiklik kaydi tamamlandi.';
    } else {
        statusNode.innerHTML = '<span class="remediation-status-pill remediation-status-open">Onay Bekliyor</span> Eksik alanlari tamamlayin.';
    }
}

function setApprovalGateCheck(key, checked){
    if (!changeApprovalGateStore || typeof changeApprovalGateStore !== 'object') changeApprovalGateStore = {};
    changeApprovalGateStore[key] = !!checked;
    saveChangeApprovalGate();
    updateApprovalGateStatus();
}

function setApprovalGateField(key, value){
    if (!changeApprovalGateStore || typeof changeApprovalGateStore !== 'object') changeApprovalGateStore = {};
    changeApprovalGateStore[key] = String(value || '');
    saveChangeApprovalGate();
    updateApprovalGateStatus();
}

function initChangeApprovalGate(){
    loadChangeApprovalGate();
    ['impact','testPlan','backout','evidence'].forEach(function(k){
        var cb = document.getElementById('approval_' + k);
        if (cb) cb.checked = !!changeApprovalGateStore[k];
    });
    ['ticket','owner','window','rollback'].forEach(function(k){
        var input = document.getElementById('approval_' + k);
        if (input) input.value = String(changeApprovalGateStore[k] || '');
    });
    updateApprovalGateStatus();
}

function remediationStatusMeta(status){
    var s = normalizeRemediationStatus(status);
    if (s === 'fixing') return { cls: 'remediation-status-pill remediation-status-fix', label: 'Fixing' };
    if (s === 'accepted') return { cls: 'remediation-status-pill remediation-status-accepted', label: 'Accepted' };
    if (s === 'exception') return { cls: 'remediation-status-pill remediation-status-exception', label: 'Exception' };
    return { cls: 'remediation-status-pill remediation-status-open', label: 'Open' };
}

function findingKeyFromRow(row){
    if (!row || !row.cells || row.cells.length < 3) return '';
    var category = (row.cells[0].innerText || '').trim();
    var rule = (row.cells[2].innerText || '').trim();
    return category + '||' + rule;
}

function initRemediationTracking(){
    loadRemediationTracking();
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    rows.forEach(function(row){
        if (!row.cells || row.cells.length < 8) return;
        var key = findingKeyFromRow(row);
        var statusCell = row.cells[6];
        if (!statusCell) return;

        var entry = getTrackingEntry(key);
        updateTrackingRowUI(row, entry);
    });

    filterRemediationStatus(currentTrackingFilter || 'all');
}

function setFindingStatus(selectEl){
    var row = selectEl;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;
    var key = findingKeyFromRow(row);
    var status = normalizeRemediationStatus(selectEl.value || 'open');
    var entry = getTrackingEntry(key);
    entry.status = status;
    setTrackingEntry(key, entry);

    var pill = row.querySelector('[data-remediation-pill="1"]');
    if (pill) {
        var meta = remediationStatusMeta(status);
        pill.className = meta.cls + ' remediation-status-pill-live';
        pill.textContent = meta.label;
    }

    filterRemediationStatus(currentTrackingFilter || 'all');
}

function setFindingNote(inputEl){
    var row = inputEl;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;
    var key = findingKeyFromRow(row);
    var entry = getTrackingEntry(key);
    entry.note = String(inputEl.value || '');
    setTrackingEntry(key, entry);
    filterRemediationStatus(currentTrackingFilter || 'all');
}

function saveRemediationRow(btn){
    var row = btn;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;
    var key = findingKeyFromRow(row);
    var selectEl = row.querySelector('.remediation-status-select');
    var noteInput = row.querySelector('.remediation-note-input');
    var entry = {
        status: normalizeRemediationStatus(selectEl ? selectEl.value : 'open'),
        note: String(noteInput ? noteInput.value : ''),
        updatedAt: new Date().toISOString()
    };
    var saved = persistTrackingEntry(key, entry);
    updateTrackingRowUI(row, saved);
    var confirmNode = row.querySelector('[data-remediation-save-status="1"]');
    if (confirmNode) {
        confirmNode.textContent = 'Kaydedildi ✓';
        confirmNode.style.display = 'inline-block';
        window.setTimeout(function(){
            confirmNode.style.display = 'none';
        }, 1500);
    }
    filterRemediationStatus(currentTrackingFilter || 'all');
}

function filterRemediationStatus(mode){
    currentTrackingFilter = String(mode || 'all').toLowerCase();
    if (currentTrackingFilter === 'fix') currentTrackingFilter = 'fixing';
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;
    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var visible = 0;
    var counts = { open: 0, fixing: 0, accepted: 0, exception: 0 };

    rows.forEach(function(row){
        var key = findingKeyFromRow(row);
        var status = normalizeRemediationStatus(getTrackingEntry(key).status);
        if (Object.prototype.hasOwnProperty.call(counts, status)) counts[status] += 1;
        var show = (currentTrackingFilter === 'all') || (status === currentTrackingFilter);
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    var chips = Array.from(document.querySelectorAll('.track-focus-chip'));
    chips.forEach(function(chip){
        var v = chip.getAttribute('data-track') || 'all';
        if (v === currentTrackingFilter) chip.classList.add('active');
        else chip.classList.remove('active');
    });

    var summary = document.getElementById('trackingSummary');
    if (summary) summary.innerText = counts.open + ' open, ' + counts.fixing + ' fixing, ' + counts.accepted + ' accepted, ' + counts.exception + ' exception | filter: ' + currentTrackingFilter + ' | shown: ' + visible;
    updateHashFromState();
}

function exportRemediationTrackingJson(){
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;
    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var payload = rows.map(function(row){
        var key = findingKeyFromRow(row);
        var entry = getTrackingEntry(key);
        return {
            Category: (row.cells[0] ? row.cells[0].innerText.trim() : ''),
            Rule: (row.cells[2] ? row.cells[2].innerText.trim() : ''),
            Severity: (row.cells[1] ? row.cells[1].innerText.trim() : ''),
            Status: normalizeRemediationStatus(entry.status || 'open'),
            Note: String(entry.note || ''),
            UpdatedAt: String(entry.updatedAt || '')
        };
    });

    var blob = new Blob([JSON.stringify({
        GeneratedAt: new Date().toISOString(),
        ChangeApproval: getChangeApprovalSnapshot(),
        Findings: payload
    }, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'remediation_tracking.json';
    a.click();
    URL.revokeObjectURL(a.href);
}

function exportRemediationTrackingExcel(){
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;

    function toUtf16LeBytes(str){
        var buffer = new ArrayBuffer(str.length * 2);
        var view = new DataView(buffer);
        for (var i = 0; i < str.length; i++) {
            view.setUint16(i * 2, str.charCodeAt(i), true);
        }
        return new Uint8Array(buffer);
    }

    var rows = Array.from(table.querySelectorAll('tr')).slice(1).map(function(row){
        var key = findingKeyFromRow(row);
        var entry = getTrackingEntry(key);
        return [
            row.cells[0] ? row.cells[0].innerText.trim() : '',
            row.cells[2] ? row.cells[2].innerText.trim() : '',
            row.cells[1] ? row.cells[1].innerText.trim() : '',
            normalizeRemediationStatus(entry.status || 'open'),
            String(entry.note || ''),
            String(entry.updatedAt || '')
        ];
    });

    var csv = ['"Category";"Rule";"Severity";"Status";"Note";"UpdatedAt"'];
    rows.forEach(function(cols){
        csv.push(cols.map(function(col){ return '"' + String(col).replace(/"/g, '""') + '"'; }).join(';'));
    });

    var payload = 'sep=;\r\n' + csv.join('\r\n');
    var utf16Payload = toUtf16LeBytes('\uFEFF' + payload);
    var blob = new Blob([utf16Payload], { type: 'text/csv;charset=utf-16le;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sanitizeFileName('remediation_tracking_states') + '.csv';
    link.click();
    URL.revokeObjectURL(link.href);
}

function openPrintHtml(title, htmlBody){
    var w = window.open('', '_blank');
    if (!w) return;
    w.document.write('<html><head><meta charset="utf-8"><title>' + title + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;padding:20px;color:#1c2d3f}h1{margin:0 0 8px 0}h2{margin:16px 0 8px 0}ul{margin:6px 0 12px 18px}li{margin-bottom:6px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #a7b9cc;padding:6px;text-align:left}th{background:#eaf1f8}.small{font-size:12px;color:#4a5f75}</style></head><body>');
    w.document.write(htmlBody);
    w.document.write('</body></html>');
    w.document.close();
    w.focus();
    w.print();
}

function exportExecutiveSummaryPdf(){
    var topFindings = safeArray(Object.values(PingRuleDetailsMap))
        .filter(function(f){ return Number(getPingCount(f) || 0) > 0; })
        .sort(function(a,b){
            var order = {Critical:0,High:1,Medium:2,Low:3};
            return (order[getPingSeverity(a)] || 9) - (order[getPingSeverity(b)] || 9) || (Number(getPingCount(b) || 0) - Number(getPingCount(a) || 0));
        })
        .slice(0, 5);

    var scoreColor = execScore < 40 ? '#c0392b' : execScore < 70 ? '#e67e22' : '#27ae60';
    var sevColors = {Critical:'#fde8e8',High:'#fef3e2',Medium:'#fefce8',Low:'#eafaf1'};
    var sevText = {Critical:'#7b1e1e',High:'#7a3e00',Medium:'#7a6b00',Low:'#155a2d'};

    var body = '<html><head><meta charset="utf-8">';
    body += '<style>';body+= '@page{size:A4;margin:18mm 20mm}';body+= 'body{font-family:Arial,sans-serif;font-size:10.5pt;color:#1a2535;margin:0}';body+= '@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact}.no-print{display:none !important}}';body+= '.header{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #0f2f4f;padding-bottom:10px;margin-bottom:14px;gap:16px}';body+= '.brand{display:flex;gap:10px;align-items:center}';body+= '.logo-box{width:42px;height:42px;border-radius:10px;background:#0f2f4f;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:15pt}';body+= '.header-left h1{margin:0;font-size:17pt;color:#0f2f4f}';body+= '.header-left p{margin:3px 0 0;font-size:9pt;color:#556}';body+= '.score-box{text-align:center;background:'+scoreColor+';color:#fff;border-radius:8px;padding:8px 14px;min-width:92px}';body+= '.score-box .num{font-size:28pt;font-weight:700;line-height:1}';body+= '.score-box .lbl{font-size:8pt;margin-top:2px}';body+= '.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}';body+= '.meta-card{border:1px solid #d0dcea;border-radius:6px;padding:8px;text-align:center}';body+= '.meta-card .val{font-size:18pt;font-weight:700;line-height:1.05}';body+= '.meta-card .lbl{font-size:8pt;color:#666;margin-top:2px}';body+= '.crit{color:#c0392b}.high{color:#e67e22}.med{color:#f1c40f}.low{color:#27ae60}';body+= 'table{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:9pt}';body+= 'th{background:#0f2f4f;color:#fff;padding:6px 8px;text-align:left}';body+= 'td{padding:5px 8px;border-bottom:1px solid #e8eef5;vertical-align:top}';body+= 'tr:nth-child(even) td{background:#f7fafd}';body+= '.sev-badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:8pt;font-weight:700}';body+= '.summary-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:12px;margin-bottom:12px}';body+= '.summary-card{border:1px solid #d0dcea;border-radius:8px;padding:10px;background:#f9fcff}';body+= '.summary-card h2{margin:0 0 8px 0;font-size:12pt;color:#0f2f4f}';body+= '.summary-list{margin:0;padding-left:18px}';body+= '.summary-list li{margin-bottom:4px}';body+= '.sig-section{margin-top:16px;display:grid;grid-template-columns:1fr 1fr;gap:26px}';body+= '.sig-box{border-top:1px solid #888;padding-top:6px;font-size:9pt;color:#555}';body+= '.footer{position:fixed;bottom:0;left:0;right:0;font-size:8pt;color:#aaa;text-align:center;padding:4px;border-top:1px solid #eee;background:#fff}';body+= '</style></head><body>';
    body += '<div class="header">';
    body += '<div class="header-left">';
    body += '<div class="brand"><div class="logo-box">AD</div><div><h1>AD Security Risk Summary</h1><p>Domain: <b>' + execDomain + '</b> &nbsp;|&nbsp; Generated: <b>' + execDate + '</b></p></div></div>';
    body += '<p>Previous snapshot: <b>' + execPreviousDate + '</b> &nbsp;|&nbsp; Previous score: <b>' + execPreviousScore + '</b></p>';
    body += '</div>';
    body += '<div class="score-box"><div class="num">' + execScore + '</div><div class="lbl">Risk / ' + execRating + '</div></div>';
    body += '</div>';
    body += '<div class="meta-grid">';
    var counts = [
        { lbl: 'Critical', cls: 'crit', val: execCritical },
        { lbl: 'High', cls: 'high', val: execHigh },
        { lbl: 'Medium', cls: 'med', val: execMedium },
        { lbl: 'Low', cls: 'low', val: execLow }
    ];
    counts.forEach(function(c){
        body += '<div class="meta-card"><div class="val ' + c.cls + '">' + c.val + '</div><div class="lbl">' + c.lbl + '</div></div>';
    });
    body += '</div>';
    body += '<div class="summary-grid">';
    body += '<div class="summary-card"><h2>Top 5 Active Findings</h2><table><tr><th>Category</th><th>Rule</th><th>Severity</th><th>Count</th><th>Action</th></tr>';
    if (!topFindings.length) {
        body += '<tr><td colspan="5">No active Critical/High/Medium/Low finding found.</td></tr>';
    } else {
        topFindings.forEach(function(f){
            var sev = String(getPingSeverity(f) || '-');
            var bg = sevColors[sev] || '#fff';
            var tc = sevText[sev] || '#333';
            body += '<tr>';
            body += '<td>' + escapeHtml(String(getPingCategory(f) || '-')) + '</td>';
            body += '<td>' + escapeHtml(String(getPingRule(f) || '-')) + '</td>';
            body += '<td><span class="sev-badge" style="background:' + bg + ';color:' + tc + '">' + escapeHtml(sev) + '</span></td>';
            body += '<td>' + escapeHtml(String(getPingCount(f) || '0')) + '</td>';
            body += '<td>' + escapeHtml(getPingAction(f) || String(f.Recommendation || f.About || '')) + '</td>';
            body += '</tr>';
        });
    }
    body += '</table></div>';
    body += '<div class="summary-card"><h2>Recommended Sequence</h2><ol class="summary-list"><li>Contain Tier-0 and privileged account exposure.</li><li>Close delegation and ACL abuse paths.</li><li>Clean stale identities and enforce hygiene controls.</li><li>Track remediation status and exceptions with owner and note.</li><li>Re-run report and compare baseline diff.</li></ol></div>';
    body += '</div>';
    body += '<div class="sig-section"><div class="sig-box">Hazırlayan: ___________________________<br>Tarih: ___________</div><div class="sig-box">Onaylayan: ___________________________<br>Tarih: ___________</div></div>';
    body += '<div class="footer">This report was generated automatically by KusoADCheck. Confidential - Internal Use Only.</div>';
    body += '</body></html>';
    openPrintHtml('Executive_AD_Risk_Summary', body);
}

function exportRemediationChecklistPdf(){
    var items = safeArray(quickRemediationItems);
    var findings = safeArray(priorityRiskFindings);
    var body = '';
    body += '<h1>Remediation Checklist</h1>';
    body += '<p class="small">Generated: ' + new Date().toLocaleString() + '</p>';
    body += '<h2>Category Actions</h2><ul>';
    if (!items.length) {
        body += '<li>No category action item available.</li>';
    } else {
        items.forEach(function(i){
            body += '<li>[ ] <b>' + String(i.Category || '-') + ' (' + String(i.RiskPct || 0) + '%)</b> - ' + String(i.Action || '').replace(/</g,'&lt;') + '</li>';
        });
    }
    body += '</ul><h2>Critical/High Findings</h2><ul>';
    if (!findings.length) {
        body += '<li>No active Critical/High finding.</li>';
    } else {
        findings.forEach(function(f){
            body += '<li>[ ] <b>[' + String(f.Severity || '-') + ']</b> ' + String(f.Rule || '-') + ' - ' + String(f.Recommendation || '').replace(/</g,'&lt;') + '</li>';
        });
    }
    body += '</ul><h2>Closure</h2><ul><li>[ ] Evidence attached</li><li>[ ] Owner assigned</li><li>[ ] Re-test scheduled</li></ul>';
    openPrintHtml('Remediation_Checklist', body);
}

function showMembers(groupName, samAccountName) {
    var membersMap = getGroupMembers();
    var members = membersMap ? membersMap[samAccountName] : null;
    if (members && Array.isArray(members) && members.length > 0) {
        var memberArray = members;
        var memberList = memberArray.join('\n');
        
        var message = 'Group Name: ' + groupName + '\n' +
                      'SAM Account: ' + samAccountName + '\n' +
                      'Member Count: ' + memberArray.length + '\n\n' +
                      'Members:\n' + memberList;
        
        alert(message);
    } else {
        ensureGroupMembersLoaded(function(){
            var loadedMembersMap = getGroupMembers() || {};
            var loadedMembers = loadedMembersMap[samAccountName];
            if (loadedMembers && Array.isArray(loadedMembers) && loadedMembers.length > 0) {
                showMembers(groupName, samAccountName);
                return;
            }
            alert(groupName + ' group has no member data or member count is 0.');
        });
    }
}

function showObjectRiskDetails(detailKey, title) {
    var riskMap = getObjectRiskDetails();
    var detailsRaw = riskMap ? riskMap[detailKey] : null;
    var details = Array.isArray(detailsRaw) ? detailsRaw : (detailsRaw ? [String(detailsRaw)] : []);
    if (details.length > 0) {
        alert(title + '\n\n' + details.join('\n'));
    } else {
        ensureObjectRiskDetailsLoaded(function(){
            var loadedRiskMap = getObjectRiskDetails() || {};
            var loadedDetailsRaw = loadedRiskMap[detailKey];
            var loadedDetails = Array.isArray(loadedDetailsRaw) ? loadedDetailsRaw : (loadedDetailsRaw ? [String(loadedDetailsRaw)] : []);
            if (loadedDetails.length > 0) {
                showObjectRiskDetails(detailKey, title);
                return;
            }
            alert(title + '\n\nNo detail data available.');
        });
    }
}

function getPingAbout(ruleData){
    return (ruleData && (ruleData.a || ruleData.About)) || 'AD security finding';
}

function getPingSource(ruleData){
    return (ruleData && (ruleData.o || ruleData.Source)) || 'Directory attributes and related checks';
}

function getPingAction(ruleData){
    return (ruleData && (ruleData.u || ruleData.Action)) || (ruleData && (ruleData.p || ruleData.Recommendation)) || 'Apply remediation steps based on the specific rule context.';
}

function getPingCategory(ruleData){ return (ruleData && (ruleData.c || ruleData.Category)) || ''; }
function getPingRule(ruleData){ return (ruleData && (ruleData.r || ruleData.Rule)) || ''; }
function getPingSeverity(ruleData){ return (ruleData && (ruleData.s || ruleData.Severity)) || ''; }
function getPingCount(ruleData){ return (ruleData && (ruleData.n || ruleData.Count)) || 0; }
function getPingSample(ruleData){ return (ruleData && (ruleData.m || ruleData.Sample)) || ''; }
function getPingRecommendation(ruleData){ return (ruleData && (ruleData.p || ruleData.Recommendation)) || ''; }
function getPingReference(ruleData){ return (ruleData && (ruleData.f || ruleData.Reference)) || ''; }
function getPingDetails(ruleData){ return (ruleData && (ruleData.d || ruleData.Details)) || []; }

function showReplicationHealth(dcName, detail) {
    var text = detail;
    if (!text || String(text).trim() === '') {
        text = 'No replication detail available.';
    }
    alert('DC: ' + dcName + '\n\nReplication Detail:\n' + text);
}

function showPingFindingDetails(category, rule) {
    var key = category + '||' + rule;
    var data = PingRuleDetailsMap[key];
    if (!data) {
        alert('No detail data available for this finding.');
        return;
    }

    var lines = [];
    lines.push('Category: ' + (getPingCategory(data) || category));
    lines.push('Rule: ' + (getPingRule(data) || rule));
    lines.push('Severity: ' + (getPingSeverity(data) || '-'));
    lines.push('Count: ' + (getPingCount(data) || 0));
    lines.push('');
    lines.push('About: ' + getPingAbout(data));
    lines.push('Source: ' + getPingSource(data));
    lines.push('Reference: ' + (getPingReference(data) || '-'));
    lines.push('Action: ' + getPingAction(data));
    lines.push('Sample: ' + (getPingSample(data) || '-'));

    var details = Array.isArray(getPingDetails(data)) ? getPingDetails(data).slice() : [];

    // Enrich privileged review rules with exact member lists from ObjectRiskDetails map.
    if (rule.indexOf('Privileged Review: ') === 0) {
        var objectName = rule.replace('Privileged Review: ', '').trim();
        var detailKey = objectName.replace(/[^a-zA-Z0-9_-]/g, '_');
        var objectRiskMap = getObjectRiskDetails();
        var usersRaw = objectRiskMap[detailKey + '|users'];
        var compsRaw = objectRiskMap[detailKey + '|computers'];
        var indirectRaw = objectRiskMap[detailKey + '|indirect'];
        var unresolvedRaw = objectRiskMap[detailKey + '|unresolved'];

        var users = Array.isArray(usersRaw) ? usersRaw : (usersRaw ? [String(usersRaw)] : []);
        var comps = Array.isArray(compsRaw) ? compsRaw : (compsRaw ? [String(compsRaw)] : []);
        var indirect = Array.isArray(indirectRaw) ? indirectRaw : (indirectRaw ? [String(indirectRaw)] : []);
        var unresolved = Array.isArray(unresolvedRaw) ? unresolvedRaw : (unresolvedRaw ? [String(unresolvedRaw)] : []);

        details.push('Users -> ' + (users.length ? users.join(', ') : 'No data'));
        details.push('Computers -> ' + (comps.length ? comps.join(', ') : 'No data'));
        details.push('Indirect Groups -> ' + (indirect.length ? indirect.join(', ') : 'No data'));
        details.push('Unresolved -> ' + (unresolved.length ? unresolved.join(', ') : 'No data'));
    }

    lines.push('');
    lines.push('Triggered By / Detail:');
    if (details.length > 0) {
        for (var i = 0; i < details.length; i++) {
            lines.push('- ' + details[i]);
        }
    } else {
        lines.push('- No detailed object/user list available for this rule.');
    }

    alert(lines.join('\n'));
}

function parseTrDate(input) {
    // Parses dd/MM/yyyy or dd/MM/yyyy HH:mm formats deterministically.
    var m = input.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2}))?$/);
    if (!m) return NaN;

    var day = parseInt(m[1], 10);
    var month = parseInt(m[2], 10) - 1;
    var year = parseInt(m[3], 10);
    var hour = m[4] ? parseInt(m[4], 10) : 0;
    var minute = m[5] ? parseInt(m[5], 10) : 0;
    return new Date(year, month, day, hour, minute, 0, 0).getTime();
}


function sortTable(tableId, columnIndex){
    var table = document.getElementById(tableId);
    var rows = Array.from(table.rows).slice(1);
    if(table.sortedColumn === columnIndex){
        table.asc = !table.asc;
    } else {
        table.asc = true;
    }
    table.sortedColumn = columnIndex;

    rows.sort(function(a,b){
        var x = a.cells[columnIndex].innerText.trim();
        var y = b.cells[columnIndex].innerText.trim();
        var dateX = parseTrDate(x);
        var dateY = parseTrDate(y);

        if (isNaN(dateX)) dateX = Date.parse(x);
        if (isNaN(dateY)) dateY = Date.parse(y);

        if(!isNaN(dateX) && !isNaN(dateY)){ x=dateX; y=dateY; }
        // Extra check: "Expired" value
        else if(x.startsWith("Expired") || y.startsWith("Expired")){
             var isXExpired = x.startsWith("Expired");
             var isYExpired = y.startsWith("Expired");
             
             if (isXExpired && !isYExpired) return table.asc ? -1 : 1; 
             if (!isXExpired && isYExpired) return table.asc ? 1 : -1; 
        }
        // Yes/No comparison
        else if((x.toLowerCase() == "yes" || x.toLowerCase() == "no") && (y.toLowerCase() == "yes" || y.toLowerCase() == "no")){
             x = (x.toLowerCase() == "yes") ? 1 : 0;
             y = (y.toLowerCase() == "yes") ? 1 : 0;
        }
        // Number comparison
        else if(!isNaN(parseFloat(x)) && !isNaN(parseFloat(y))){ x=parseFloat(x); y=parseFloat(y); }
        // Text comparison
        else { x=x.toLowerCase(); y=y.toLowerCase(); }

        if(x < y) return table.asc ? -1 : 1;
        if(x > y) return table.asc ? 1 : -1;
        return 0;
    });

    for(var i=0;i<rows.length;i++){ table.appendChild(rows[i]); }
}

function ipToNumber(ipText){
    var m = (ipText || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if(!m) return NaN;
    var a = parseInt(m[1],10), b = parseInt(m[2],10), c = parseInt(m[3],10), d = parseInt(m[4],10);
    return (((a * 256) + b) * 256 + c) * 256 + d;
}

function sortNetworkTableByIP(tableId, columnIndex){
    var table = document.getElementById(tableId);
    if(!table) return;
    var rows = Array.from(table.rows).slice(1);

    if(table.networkSortedColumn === columnIndex){
        table.networkAsc = !table.networkAsc;
    } else {
        table.networkAsc = true;
    }
    table.networkSortedColumn = columnIndex;

    rows.sort(function(a,b){
        var x = ipToNumber(a.cells[columnIndex].innerText);
        var y = ipToNumber(b.cells[columnIndex].innerText);

        if (isNaN(x) && isNaN(y)) return 0;
        if (isNaN(x)) return table.networkAsc ? 1 : -1;
        if (isNaN(y)) return table.networkAsc ? -1 : 1;
        if (x < y) return table.networkAsc ? -1 : 1;
        if (x > y) return table.networkAsc ? 1 : -1;
        return 0;
    });

    rows.forEach(function(row){ table.appendChild(row); });
}

function applyDefaultNetworkOrdering(){
    var table = document.getElementById('networkDiscoveryTable');
    if(!table) return;

    var rows = Array.from(table.rows).slice(1);
    rows.sort(function(a, b){
        var statusA = (a.cells[0] ? a.cells[0].innerText : '').trim().toLowerCase();
        var statusB = (b.cells[0] ? b.cells[0].innerText : '').trim().toLowerCase();

        var rankA = (statusA === 'up') ? 0 : 1;
        var rankB = (statusB === 'up') ? 0 : 1;
        if (rankA !== rankB) return rankA - rankB;

        var ipA = ipToNumber(a.cells[1] ? a.cells[1].innerText : '');
        var ipB = ipToNumber(b.cells[1] ? b.cells[1].innerText : '');

        if (isNaN(ipA) && isNaN(ipB)) return 0;
        if (isNaN(ipA)) return 1;
        if (isNaN(ipB)) return -1;
        return ipA - ipB;
    });

    rows.forEach(function(row){ table.appendChild(row); });
}

function sanitizeFileName(name){
    return name.replace(/[^a-z0-9\-_]+/gi, '_');
}

function exportTableToExcel(tableId, fileName){
    var table = document.getElementById(tableId);
    if(!table) return;

    function toUtf16LeBytes(str){
        var buffer = new ArrayBuffer(str.length * 2);
        var view = new DataView(buffer);
        for (var i = 0; i < str.length; i++) {
            view.setUint16(i * 2, str.charCodeAt(i), true);
        }
        return new Uint8Array(buffer);
    }

    var csv = [];
    var rows = table.querySelectorAll('tr');
    rows.forEach(function(row){
        var cols = row.querySelectorAll('th,td');
        var vals = [];
        cols.forEach(function(col){
            var text = (col.innerText || '').replace(/\r?\n|\r/g, ' ');
            vals.push('"' + text.replace(/"/g, '""') + '"');
        });
        csv.push(vals.join(';'));
    });

    // Use UTF-16LE + BOM + separator hint for reliable Turkish characters in Excel.
    var csvContent = 'sep=;\r\n' + csv.join('\r\n');
    var utf16Payload = toUtf16LeBytes('\uFEFF' + csvContent);
    var blob = new Blob([utf16Payload], { type: 'text/csv;charset=utf-16le;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sanitizeFileName(fileName) + '.csv';
    link.click();
    URL.revokeObjectURL(link.href);
}

function exportTableToWord(tableId, fileName){
    var table = document.getElementById(tableId);
    if(!table) return;

    var html = '<html><head><meta charset="utf-8"></head><body>' + table.outerHTML + '</body></html>';
    var blob = new Blob(['\ufeff', html], { type: 'application/msword' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sanitizeFileName(fileName) + '.doc';
    link.click();
    URL.revokeObjectURL(link.href);
}

function exportTableToPdf(tableId, title){
    var table = document.getElementById(tableId);
    if(!table) return;

    var w = window.open('', '_blank');
    w.document.write('<html><head><title>' + title + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;padding:16px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #999;padding:6px;text-align:left}th{background:#eee}</style></head><body>');
    w.document.write('<h2>' + title + '</h2>');
    w.document.write(table.outerHTML);
    w.document.write('</body></html>');
    w.document.close();
    w.focus();
    w.print();
}

function addExportButtonsToTables(){
    var tables = document.querySelectorAll('.container table.user-table');
    tables.forEach(function(table){
        if (!table.id) return;

        // Export buttons for PingCastle category tables are added server-side.
        if (table.id.indexOf('pingCastleCategory') === 0) return;

        var previous = table.previousElementSibling;
        if (previous && previous.classList && previous.classList.contains('export-actions')) return;

        var actions = document.createElement('div');
        actions.className = 'export-actions';

        var btnExcel = document.createElement('button');
        btnExcel.className = 'export-btn';
        btnExcel.innerText = 'Excel';
        btnExcel.onclick = function(){ exportTableToExcel(table.id, table.id); };

        var btnWord = document.createElement('button');
        btnWord.className = 'export-btn';
        btnWord.innerText = 'Word';
        btnWord.onclick = function(){ exportTableToWord(table.id, table.id); };

        var btnPdf = document.createElement('button');
        btnPdf.className = 'export-btn';
        btnPdf.innerText = 'PDF';
        btnPdf.onclick = function(){ exportTableToPdf(table.id, table.id); };

        actions.appendChild(btnExcel);
        actions.appendChild(btnWord);
        actions.appendChild(btnPdf);

        table.parentNode.insertBefore(actions, table);
    });
}

function focusPingCategory(tableId){
    showLoadingAndContent('pingCastleRisksContainer');
    setTimeout(function(){
        var table = document.getElementById(tableId);
        if(!table) return;
        table.scrollIntoView({ behavior: 'smooth', block: 'start' });
        table.classList.add('ping-focus-table');
        setTimeout(function(){ table.classList.remove('ping-focus-table'); }, 2200);
    }, 480);
}

function focusPingRule(ruleName){
    showLoadingAndContent('pingCastleRisksContainer');
    setTimeout(function(){
        var table = document.getElementById('pingCastleRiskTable');
        if(!table) return;

        var rows = Array.from(table.querySelectorAll('tr')).slice(1);
        var targetRow = null;
        rows.forEach(function(row){ row.classList.remove('ping-focus-row'); });

        for (var i = 0; i < rows.length; i++) {
            var ruleCell = rows[i].cells[2];
            if (ruleCell && ruleCell.innerText.trim() === ruleName) {
                targetRow = rows[i];
                break;
            }
        }

        if (targetRow) {
            targetRow.classList.add('ping-focus-row');
            targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
            setTimeout(function(){ targetRow.classList.remove('ping-focus-row'); }, 2500);
        }
    }, 480);
}

function applyBaselineDiffFilter(changeType){
    currentBaselineChangeFilter = changeType || 'all';
    var table = document.getElementById('pingBaselineDiffTable');
    if (!table) return;

    var searchEl = document.getElementById('baselineDiffSearch');
    var fieldEl = document.getElementById('baselineDiffField');
    var searchTerm = searchEl ? String(searchEl.value || '').toLowerCase().trim() : '';
    var fieldMode = fieldEl ? String(fieldEl.value || 'all') : 'all';

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var visible = 0;
    var newCount = 0;
    var changedCount = 0;
    var resolvedCount = 0;

    rows.forEach(function(row){
        var cells = row.cells;
        if (!cells || cells.length < 1) {
            row.style.display = '';
            return;
        }

        var isInfoRow = (cells.length === 1) && ((cells[0].colSpan || 1) > 1);
        if (isInfoRow) {
            row.style.display = (currentBaselineChangeFilter === 'all' && !searchTerm) ? '' : 'none';
            return;
        }

        var typeText = (cells[0].innerText || '').trim().toLowerCase();
        var typeMatch = (currentBaselineChangeFilter === 'all') || (typeText === currentBaselineChangeFilter);

        var haystack = '';
        if (fieldMode === 'rule') haystack = (cells[2] && cells[2].innerText) ? cells[2].innerText : '';
        else if (fieldMode === 'category') haystack = (cells[1] && cells[1].innerText) ? cells[1].innerText : '';
        else if (fieldMode === 'delta') haystack = (cells[7] && cells[7].innerText) ? cells[7].innerText : '';
        else if (fieldMode === 'action') haystack = (cells[8] && cells[8].innerText) ? cells[8].innerText : '';
        else haystack = row.innerText || '';

        var searchMatch = (!searchTerm) || (String(haystack).toLowerCase().indexOf(searchTerm) !== -1);
        var show = typeMatch && searchMatch;
        row.style.display = show ? '' : 'none';
        if (show) {
            visible++;
            if (typeText === 'new') newCount++;
            else if (typeText === 'changed') changedCount++;
            else if (typeText === 'resolved') resolvedCount++;
        }
    });

    var chips = Array.from(document.querySelectorAll('.baseline-focus-chip'));
    chips.forEach(function(chip){
        var mode = chip.getAttribute('data-mode') || 'all';
        if (mode === currentBaselineChangeFilter) chip.classList.add('active');
        else chip.classList.remove('active');
    });

    var cards = Array.from(document.querySelectorAll('.baseline-hero-card'));
    cards.forEach(function(card){
        var mode = card.getAttribute('data-mode') || 'all';
        if (mode === currentBaselineChangeFilter) card.classList.add('active');
        else card.classList.remove('active');
    });

    var totalCount = (currentBaselineChangeFilter === 'all') ? visible : (newCount + changedCount + resolvedCount);

    var newEl = document.getElementById('baselineCountNew');
    var changedEl = document.getElementById('baselineCountChanged');
    var resolvedEl = document.getElementById('baselineCountResolved');
    var totalEl = document.getElementById('baselineCountTotal');
    if (newEl) newEl.innerText = newCount;
    if (changedEl) changedEl.innerText = changedCount;
    if (resolvedEl) resolvedEl.innerText = resolvedCount;
    if (totalEl) totalEl.innerText = totalCount;

    var newPct = totalCount > 0 ? ((newCount * 100) / totalCount) : 0;
    var changedPct = totalCount > 0 ? ((changedCount * 100) / totalCount) : 0;
    var resolvedPct = totalCount > 0 ? ((resolvedCount * 100) / totalCount) : 0;

    var barNew = document.getElementById('baselineBarNew');
    var barChanged = document.getElementById('baselineBarChanged');
    var barResolved = document.getElementById('baselineBarResolved');
    if (barNew) barNew.style.width = newPct.toFixed(1) + '%';
    if (barChanged) barChanged.style.width = changedPct.toFixed(1) + '%';
    if (barResolved) barResolved.style.width = resolvedPct.toFixed(1) + '%';

    var pctNewEl = document.getElementById('baselinePctNew');
    var pctChangedEl = document.getElementById('baselinePctChanged');
    var pctResolvedEl = document.getElementById('baselinePctResolved');
    if (pctNewEl) pctNewEl.innerText = newPct.toFixed(1);
    if (pctChangedEl) pctChangedEl.innerText = changedPct.toFixed(1);
    if (pctResolvedEl) pctResolvedEl.innerText = resolvedPct.toFixed(1);

    var summary = document.getElementById('pingBaselineFilterSummary');
    if (summary) {
        var searchInfo = searchTerm ? (' | Search: ' + searchTerm) : '';
        summary.innerText = visible + ' rows listed | New ' + newCount + ' | Changed ' + changedCount + ' | Resolved ' + resolvedCount + searchInfo;
    }
}

function openRiskBaselineWithFilter(changeType){
    showLoadingAndContent('pingBaselineDiffContainer');
    setTimeout(function(){ applyBaselineDiffFilter(changeType || 'all'); }, 480);
}

function openUserRiskContainer(sectionKey){
    showLoadingAndContent('adUserRiskLevelContainer');
    setTimeout(function(){ showUserRiskSection(sectionKey || 'lockouts'); }, 480);
}

function showUserRiskSection(sectionKey){
    var sectionMap = {
        lockouts: 'userRiskSectionLockouts',
        failedUsers: 'userRiskSectionFailedUsers',
        failedSources: 'userRiskSectionFailedSources',
        spray: 'userRiskSectionSpray',
        privileged: 'userRiskSectionPrivileged',
        correlation: 'userRiskSectionCorrelation',
        userDevice: 'userRiskSectionUserDevice'
    };

    var cardMap = {
        lockouts: 'userRiskCardLockouts',
        failedUsers: 'userRiskCardFailedUsers',
        failedSources: 'userRiskCardFailedSources',
        spray: 'userRiskCardSpray',
        privileged: 'userRiskCardPrivileged',
        correlation: 'userRiskCardCorrelation',
        userDevice: 'userRiskCardUserDevice'
    };

    Object.keys(sectionMap).forEach(function(key){
        var sec = document.getElementById(sectionMap[key]);
        if (sec) { sec.style.display = (key === sectionKey ? 'block' : 'none'); }
    });

    Object.keys(cardMap).forEach(function(key){
        var card = document.getElementById(cardMap[key]);
        if (card) {
            if (key === sectionKey) { card.classList.add('active'); }
            else { card.classList.remove('active'); }
        }
    });

    if (sectionKey === 'lockouts') {
        if (!userRiskExplorerData || !userRiskExplorerData.length) {
            initUserRiskExplorer();
        }
        applyUserRiskFilters();
    } else if (sectionKey === 'failedUsers') {
        showAllFailedUsers();
    } else if (sectionKey === 'failedSources') {
        showAllFailedSources();
    } else if (sectionKey === 'spray') {
        showAllPasswordSprayCandidates();
    } else if (sectionKey === 'privileged') {
        showAllPrivilegedWatchlist();
    } else if (sectionKey === 'correlation') {
        showAllLockoutCorrelations();
    }
}

function applyPingRiskFocus(mode){
    currentRiskFocusMode = mode || 'all';
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var visible = 0;

    rows.forEach(function(row){
        var cells = row.cells;
        if (!cells || cells.length < 2) {
            row.style.display = '';
            return;
        }

        var category = (cells[0].innerText || '').toLowerCase();
        var severity = (cells[1].innerText || '').toLowerCase();
        var show = true;

        if (mode === 'critical') {
            show = (severity === 'critical');
        } else if (mode === 'criticalhigh') {
            show = (severity === 'critical' || severity === 'high');
        } else if (mode === 'privileged') {
            show = (category.indexOf('privileged') !== -1 || category.indexOf('infrastructure') !== -1);
        } else if (mode === 'anomalies') {
            show = (category.indexOf('anomalies') !== -1);
        } else if (mode === 'hygiene') {
            show = (category.indexOf('hygiene') !== -1 || category.indexOf('stale') !== -1);
        }

        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    var chips = Array.from(document.querySelectorAll('#pingRiskFocusBar .risk-focus-chip'));
    chips.forEach(function(chip){
        var chipMode = chip.getAttribute('data-mode') || 'all';
        if (chipMode === currentRiskFocusMode) chip.classList.add('active');
        else chip.classList.remove('active');
    });

    var summary = document.getElementById('pingRiskFocusSummary');
    if (summary) {
        var total = rows.length;
        summary.innerText = visible + ' of ' + total + ' findings listed';
    }
    updateHashFromState();
}

function parseRiskCountValue(text){
    var t = String(text || '').trim();
    var n = parseFloat(t.replace(/[^0-9.-]/g, ''));
    if (isNaN(n)) return 0;
    return n;
}

function getRiskTableRowsData(){
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return [];
    return Array.from(table.querySelectorAll('tr')).slice(1).map(function(row){
        var cells = row.cells || [];
        return {
            row: row,
            category: (cells[0] ? cells[0].innerText : '').trim(),
            severity: (cells[1] ? cells[1].innerText : '').trim(),
            rule: (cells[2] ? cells[2].innerText : '').trim(),
            count: parseRiskCountValue(cells[3] ? cells[3].innerText : '0')
        };
    });
}

function getCategoryPenaltyMapFromBreakdown(){
    var map = {};
    var rows = Array.from(document.querySelectorAll('.risk-breakdown-table tr')).slice(1);
    rows.forEach(function(r){
        var cells = r.cells || [];
        if (cells.length < 2) return;
        var category = (cells[0].innerText || '').trim();
        var penalty = parseRiskCountValue(cells[1].innerText || '0');
        if (category) map[category] = penalty;
    });
    return map;
}

function computeWeightedRiskScore(penaltyByCategory){
    var weightedSum = 0;
    var totalWeight = 0;
    Object.keys(riskCategoryWeightMap).forEach(function(category){
        var weight = riskCategoryWeightMap[category] || 0;
        var threshold = riskCategoryThresholdMap[category] || 100;
        var penalty = parseFloat(penaltyByCategory[category] || 0);
        var riskPct = Math.min(100, Math.max(0, (penalty / threshold) * 100));
        weightedSum += riskPct * weight;
        totalWeight += weight;
    });
    if (totalWeight <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round(weightedSum / totalWeight)));
}

function riskRatingFromScore(score){
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'Poor';
    if (score >= 40) return 'Acceptable';
    return 'Good';
}

function getCurrentRiskScoreFromGauge(){
    var node = document.querySelector('.risk-gauge-score');
    if (!node) return 0;
    var n = parseInt((node.innerText || '0').replace(/[^0-9-]/g, ''), 10);
    return isNaN(n) ? 0 : n;
}

function renderRiskImpactSimulator(){
    var host = document.getElementById('riskImpactSimulatorBody');
    if (!host) return;

    var rows = getRiskTableRowsData().filter(function(r){
        return r.count > 0 && (r.severity === 'Critical' || r.severity === 'High' || r.severity === 'Medium');
    });
    if (!rows.length) {
        host.innerHTML = '<p class="risk-model-note">No active Critical/High/Medium findings available for simulation.</p>';
        return;
    }

    var severityCounts = { Critical: 0, High: 0, Medium: 0 };
    rows.forEach(function(r){ if (severityCounts[r.severity] !== undefined) severityCounts[r.severity] += 1; });

    host.innerHTML = ''
        + '<div class="risk-sim-controls">'
        + '  <div class="risk-sim-control"><label>Close Critical Findings: <b id="simCriticalVal">0</b> / ' + severityCounts.Critical + '</label><input id="simCritical" type="range" min="0" max="' + severityCounts.Critical + '" value="0" oninput="updateRiskImpactSimulation()"></div>'
        + '  <div class="risk-sim-control"><label>Close High Findings: <b id="simHighVal">0</b> / ' + severityCounts.High + '</label><input id="simHigh" type="range" min="0" max="' + severityCounts.High + '" value="0" oninput="updateRiskImpactSimulation()"></div>'
        + '  <div class="risk-sim-control"><label>Close Medium Findings: <b id="simMediumVal">0</b> / ' + severityCounts.Medium + '</label><input id="simMedium" type="range" min="0" max="' + severityCounts.Medium + '" value="0" oninput="updateRiskImpactSimulation()"></div>'
        + '</div>'
        + '<div class="risk-sim-result" id="riskImpactResult">Simulation ready</div>';

    updateRiskImpactSimulation();
}

function updateRiskImpactSimulation(){
    var currentScore = getCurrentRiskScoreFromGauge();
    var rows = getRiskTableRowsData().filter(function(r){
        return r.count > 0 && (r.severity === 'Critical' || r.severity === 'High' || r.severity === 'Medium');
    });
    var penaltyByCategory = getCategoryPenaltyMapFromBreakdown();

    var closeCritical = parseInt((document.getElementById('simCritical') || {}).value || '0', 10) || 0;
    var closeHigh = parseInt((document.getElementById('simHigh') || {}).value || '0', 10) || 0;
    var closeMedium = parseInt((document.getElementById('simMedium') || {}).value || '0', 10) || 0;

    var vCritical = document.getElementById('simCriticalVal');
    var vHigh = document.getElementById('simHighVal');
    var vMedium = document.getElementById('simMediumVal');
    if (vCritical) vCritical.innerText = closeCritical;
    if (vHigh) vHigh.innerText = closeHigh;
    if (vMedium) vMedium.innerText = closeMedium;

    function applyCloseForSeverity(severity, closeCount){
        if (closeCount <= 0) return;
        var candidates = rows.filter(function(r){ return r.severity === severity; }).sort(function(a,b){
            var ca = parseRiskCountValue(penaltyByCategory[a.category] || 0);
            var cb = parseRiskCountValue(penaltyByCategory[b.category] || 0);
            return cb - ca;
        });
        var used = 0;
        for (var i = 0; i < candidates.length && used < closeCount; i++) {
            var c = candidates[i];
            if (penaltyByCategory[c.category] === undefined) penaltyByCategory[c.category] = 0;
            penaltyByCategory[c.category] = Math.max(0, parseFloat(penaltyByCategory[c.category]) - (riskSeverityWeightMap[severity] || 0));
            used += 1;
        }
    }

    applyCloseForSeverity('Critical', closeCritical);
    applyCloseForSeverity('High', closeHigh);
    applyCloseForSeverity('Medium', closeMedium);

    var projected = computeWeightedRiskScore(penaltyByCategory);
    var delta = currentScore - projected;
    var rating = riskRatingFromScore(projected);
    var result = document.getElementById('riskImpactResult');
    if (result) {
        result.innerHTML = 'Projected Score: <b>' + projected + '/100</b> (' + rating + ') | Improvement: <b>' + (delta >= 0 ? '-' + delta : '+' + Math.abs(delta)) + '</b>';
    }
}

function renderRiskContributionBreakdown(){
    var host = document.getElementById('riskContributionBody');
    if (!host) return;

    var penaltyByCategory = getCategoryPenaltyMapFromBreakdown();
    var scoreRawByCategory = {};
    var total = 0;

    Object.keys(riskCategoryWeightMap).forEach(function(category){
        var weight = riskCategoryWeightMap[category] || 0;
        var threshold = riskCategoryThresholdMap[category] || 100;
        var penalty = parseFloat(penaltyByCategory[category] || 0);
        var riskPct = Math.min(100, Math.max(0, (penalty / threshold) * 100));
        var contribution = (riskPct * weight) / 100;
        scoreRawByCategory[category] = contribution;
        total += contribution;
    });

    var html = '<div class="risk-contrib-list">';
    Object.keys(scoreRawByCategory)
        .sort(function(a,b){ return scoreRawByCategory[b] - scoreRawByCategory[a]; })
        .forEach(function(category){
            var value = scoreRawByCategory[category];
            var pct = total > 0 ? (value * 100 / total) : 0;
            html += '<div class="risk-contrib-row">'
                + '<div class="risk-contrib-head"><span>' + escapeHtml(category) + '</span><b>' + pct.toFixed(1) + '%</b></div>'
                + '<div class="risk-contrib-bar"><span style="width:' + pct.toFixed(1) + '%"></span></div>'
                + '</div>';
        });
    html += '</div>';

    var confLabel = (document.querySelector('.risk-confidence-chip') || {}).innerText || 'Confidence: -';
    var confNote = (document.querySelector('.risk-confidence-note') || {}).innerText || '';
    html += '<div class="risk-contrib-foot">' + escapeHtml(confLabel + ' | ' + confNote) + '</div>';
    host.innerHTML = html;
}

function loadRiskWatchlist(){
    try {
        var raw = localStorage.getItem('adcheck-risk-watchlist');
        riskWatchlistStore = raw ? JSON.parse(raw) : {};
    } catch (e) {
        riskWatchlistStore = {};
    }
}

function saveRiskWatchlist(){
    try { localStorage.setItem('adcheck-risk-watchlist', JSON.stringify(riskWatchlistStore)); } catch (e) {}
}

function buildWatchButtonHtml(active){
    var cls = active ? 'watch-btn active' : 'watch-btn';
    var txt = active ? 'Watching' : 'Watch';
    return '<button class="' + cls + '" onclick="toggleRiskWatch(this)">' + txt + '</button>';
}

function initRiskWatchlist(){
    loadRiskWatchlist();
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;
    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    rows.forEach(function(row){
        if (!row.cells || row.cells.length < 9) return;
        var key = findingKeyFromRow(row);
        var watchCell = row.cells[8];
        watchCell.innerHTML = buildWatchButtonHtml(!!riskWatchlistStore[key]);
    });
    renderRiskWatchlistPanel();
}

function toggleRiskWatch(button){
    var row = button;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;

    var key = findingKeyFromRow(row);
    if (!key) return;
    if (riskWatchlistStore[key]) delete riskWatchlistStore[key];
    else riskWatchlistStore[key] = 1;

    saveRiskWatchlist();
    var watchCell = row.cells[8];
    if (watchCell) watchCell.innerHTML = buildWatchButtonHtml(!!riskWatchlistStore[key]);
    renderRiskWatchlistPanel();
}

function renderRiskWatchlistPanel(){
    var host = document.getElementById('riskWatchlistBody');
    var countNode = document.getElementById('riskWatchlistCount');
    if (!host) return;

    var rows = getRiskTableRowsData();
    var watched = rows.filter(function(r){ return riskWatchlistStore[r.category + '||' + r.rule]; });
    if (countNode) countNode.innerText = watched.length;

    if (!watched.length) {
        host.innerHTML = '<div class="risk-watch-empty">No watchlisted rule yet.</div>';
        return;
    }

    var html = '';
    watched.slice(0, 20).forEach(function(w){
        var safeRuleJs = String(w.rule || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        html += '<div class="risk-watch-item">'
            + '<span class="risk-watch-sev">[' + escapeHtml(w.severity) + ']</span> '
            + '<span class="risk-watch-rule" onclick="focusPingRule(\'' + safeRuleJs + '\')">' + escapeHtml(w.rule) + '</span>'
            + '<span class="risk-watch-cat">' + escapeHtml(w.category) + '</span>'
            + '</div>';
    });
    host.innerHTML = html;
}

function renderDcHealthHeatmap(){
    var host = document.getElementById('dcHealthHeatmapBody');
    if (!host) return;
    var table = document.getElementById('dcHealthTable');
    if (!table) return;

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    if (!rows.length) {
        host.innerHTML = '<div class="risk-watch-empty">No DC health row available.</div>';
        return;
    }

    function scoreRow(row){
        var dns = ((row.cells[8] ? row.cells[8].innerText : '') || '').toLowerCase();
        var repl = ((row.cells[9] ? row.cells[9].innerText : '') || '').toLowerCase();
        var sysvol = ((row.cells[3] ? row.cells[3].innerText : '') || '').toLowerCase();
        var score = 100;

        if (dns.indexOf('access error') >= 0) score -= 45;
        else if (dns.indexOf('error') >= 0) score -= 40;
        else if (dns.indexOf('ok') === -1) score -= 20;

        if (repl.indexOf('error') >= 0 || repl.indexOf('access error') >= 0) score -= 45;
        else if (repl.indexOf('warn') >= 0) score -= 20;

        if (sysvol.indexOf('frs') >= 0) score -= 20;
        return Math.max(0, Math.min(100, score));
    }

    function clsByScore(s){
        if (s >= 85) return 'dc-heat-good';
        if (s >= 65) return 'dc-heat-warn';
        return 'dc-heat-bad';
    }

    var html = '<div class="dc-heat-grid">';
    rows.forEach(function(row){
        var dcName = (row.cells[0] ? row.cells[0].innerText : '-').trim();
        var dns = (row.cells[8] ? row.cells[8].innerText : '-').trim();
        var repl = (row.cells[9] ? row.cells[9].innerText : '-').trim();
        var score = scoreRow(row);
        html += '<div class="dc-heat-card ' + clsByScore(score) + '">'
            + '<div class="dc-heat-head"><b>' + escapeHtml(dcName) + '</b><span>' + score + '/100</span></div>'
            + '<div class="dc-heat-meta">DNS: ' + escapeHtml(dns) + ' | Repl: ' + escapeHtml(repl) + '</div>'
            + '<div class="dc-heat-bar"><span style="width:' + score + '%"></span></div>'
            + '</div>';
    });
    html += '</div>';
    host.innerHTML = html;
}

function userRiskSafeText(value){
    return (value === null || value === undefined || value === '') ? '-' : String(value);
}

function userRiskNormalize(value){
    return userRiskSafeText(value).toLowerCase();
}

function userRiskQuery(value){
    if (value === null || value === undefined) return '';
    return String(value).trim().toLowerCase();
}

function userRiskEsc(text){
    return userRiskSafeText(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function userRiskStatusClass(status){
    var normalized = userRiskNormalize(status);
    if (normalized === 'failed') return 'user-risk-status user-risk-status-failed';
    if (normalized === 'success') return 'user-risk-status user-risk-status-success';
    return 'user-risk-status user-risk-status-locked';
}

function userRiskSetDatalist(listId, values){
    var node = document.getElementById(listId);
    if (!node) return;
    var html = '';
    var seen = {};
    (values || []).forEach(function(val){
        var text = userRiskSafeText(val);
        if (text === '-' || seen[text]) return;
        seen[text] = true;
        html += '<option value="' + text.replace(/"/g, '&quot;') + '"></option>';
    });
    node.innerHTML = html;
}

function initUserRiskExplorer(){
    var sourceRows = Array.isArray(UserRiskActivity) ? UserRiskActivity : (UserRiskActivity ? [UserRiskActivity] : []);
    userRiskExplorerData = sourceRows.map(function(row){
        return {
            TimeIso: userRiskSafeText(row.TimeIso),
            TimeDisplay: userRiskSafeText(row.TimeDisplay),
            Status: userRiskSafeText(row.Status),
            User: userRiskSafeText(row.User),
            SourceHost: userRiskSafeText(row.SourceHost),
            SourceIP: userRiskSafeText(row.SourceIP),
            DestinationHost: userRiskSafeText(row.DestinationHost),
            DestinationIP: userRiskSafeText(row.DestinationIP),
            LogonType: userRiskSafeText(row.LogonType),
            Reason: userRiskSafeText(row.Reason)
        };
    });

    userRiskSetDatalist('userRiskUsersList', userRiskExplorerData.map(function(r){ return r.User; }));
    userRiskSetDatalist('userRiskSourcesList', userRiskExplorerData.map(function(r){ return (r.SourceHost !== '-' ? r.SourceHost : r.SourceIP); }));
    userRiskSetDatalist('userRiskDestinationsList', userRiskExplorerData.map(function(r){ return (r.DestinationHost !== '-' ? r.DestinationHost : r.DestinationIP); }));
    renderUserRisk24hSummary();

    if (!userRiskDefaultPresetApplied) {
        userRiskDefaultPresetApplied = true;
        setUserRiskQuickPreset('failed24');
        return;
    }

    applyUserRiskFilters();
}

function renderUserRisk24hSummary(){
    var node = document.getElementById('userRisk24hSummary');
    if (!node) return;

    var nowMs = Date.now();
    var cutoff = nowMs - (24 * 3600000);
    var rows = userRiskExplorerData.filter(function(r){
        var t = Date.parse(r.TimeIso);
        return (!isNaN(t) && t >= cutoff);
    });

    var failed = 0, locked = 0, success = 0;
    var users = {};
    rows.forEach(function(r){
        var s = userRiskNormalize(r.Status);
        if (s === 'failed') failed += 1;
        else if (s === 'locked') locked += 1;
        else if (s === 'success') success += 1;
        users[userRiskSafeText(r.User)] = true;
    });

    var html = '';
    html += '<span class="user-risk-kpi-chip">24h Events <b>' + rows.length + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Failed <b>' + failed + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Locked <b>' + locked + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Success <b>' + success + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Distinct Users <b>' + Object.keys(users).length + '</b></span>';
    node.innerHTML = html;
}

function initUserRiskFailedDatasets(){
    var users = Array.isArray(UserRiskFailedByUserData) ? UserRiskFailedByUserData : (UserRiskFailedByUserData ? [UserRiskFailedByUserData] : []);
    userRiskFailedUsersData = users.map(function(row){
        return {
            TargetUser: userRiskSafeText(row.TargetUser),
            FailedCount: parseInt(row.FailedCount, 10) || 0,
            LastSeenIso: userRiskSafeText(row.LastSeenIso),
            LastSeenDisplay: userRiskSafeText(row.LastSeenDisplay),
            TopSources: userRiskSafeText(row.TopSources)
        };
    });

    var sources = Array.isArray(UserRiskFailedBySourceData) ? UserRiskFailedBySourceData : (UserRiskFailedBySourceData ? [UserRiskFailedBySourceData] : []);
    userRiskFailedSourcesData = sources.map(function(row){
        return {
            Source: userRiskSafeText(row.Source),
            FailedCount: parseInt(row.FailedCount, 10) || 0,
            LastSeenIso: userRiskSafeText(row.LastSeenIso),
            LastSeenDisplay: userRiskSafeText(row.LastSeenDisplay),
            TopUsers: userRiskSafeText(row.TopUsers)
        };
    });
}

function renderFailedUsersRows(rows){
    var tbody = document.getElementById('userRiskFailedByUserTbody');
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="4">No failed logon event found for selected filters.</td></tr>';
        return;
    }

    var sorted = rows.slice().sort(function(a,b){
        var c = (parseInt(b.FailedCount, 10) || 0) - (parseInt(a.FailedCount, 10) || 0);
        if (c !== 0) return c;
        return Date.parse(b.LastSeenIso || '') - Date.parse(a.LastSeenIso || '');
    });

    var html = '';
    sorted.forEach(function(r){
        html += '<tr>' +
            '<td>' + userRiskEsc(r.TargetUser) + '</td>' +
            '<td>' + r.FailedCount + '</td>' +
            '<td>' + userRiskEsc(r.LastSeenDisplay) + '</td>' +
            '<td>' + userRiskEsc(r.TopSources) + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

function clearFailedUsersFilterInputs(){
    var ids = ['userRiskFailedUsersFilterUser', 'userRiskFailedUsersFilterSource', 'userRiskFailedUsersFilterMinCount', 'userRiskFailedUsersFilterHours'];
    ids.forEach(function(id){
        var node = document.getElementById(id);
        if (node) node.value = '';
    });
}

function showAllFailedUsers(){
    var summary = document.getElementById('userRiskFailedUsersFilterSummary');
    if (!userRiskFailedUsersData || !userRiskFailedUsersData.length) {
        initUserRiskFailedDatasets();
    }
    clearFailedUsersFilterInputs();
    renderFailedUsersRows(userRiskFailedUsersData);
    if (summary) summary.innerText = userRiskFailedUsersData.length + ' records listed';
}

function renderFailedSourcesRows(rows){
    var tbody = document.getElementById('userRiskFailedBySourceTbody');
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="4">No failed source found for selected filters.</td></tr>';
        return;
    }

    var sorted = rows.slice().sort(function(a,b){
        var c = (parseInt(b.FailedCount, 10) || 0) - (parseInt(a.FailedCount, 10) || 0);
        if (c !== 0) return c;
        return Date.parse(b.LastSeenIso || '') - Date.parse(a.LastSeenIso || '');
    });

    var html = '';
    sorted.forEach(function(r){
        html += '<tr>' +
            '<td>' + userRiskEsc(r.Source) + '</td>' +
            '<td>' + r.FailedCount + '</td>' +
            '<td>' + userRiskEsc(r.LastSeenDisplay) + '</td>' +
            '<td>' + userRiskEsc(r.TopUsers) + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

function clearFailedSourcesFilterInputs(){
    var ids = ['userRiskFailedSourcesFilterSource', 'userRiskFailedSourcesFilterUser', 'userRiskFailedSourcesFilterMinCount', 'userRiskFailedSourcesFilterHours'];
    ids.forEach(function(id){
        var node = document.getElementById(id);
        if (node) node.value = '';
    });
}

function showAllFailedSources(){
    var summary = document.getElementById('userRiskFailedSourcesFilterSummary');
    if (!userRiskFailedSourcesData || !userRiskFailedSourcesData.length) {
        initUserRiskFailedDatasets();
    }
    clearFailedSourcesFilterInputs();
    renderFailedSourcesRows(userRiskFailedSourcesData);
    if (summary) summary.innerText = userRiskFailedSourcesData.length + ' records listed';
}

function showAllPasswordSprayCandidates(){
    return;
}

function showAllPrivilegedWatchlist(){
    return;
}

function showAllLockoutCorrelations(){
    return;
}

function applyUserRiskFilters(){
    var status = userRiskNormalize((document.getElementById('userRiskFilterStatus') || {}).value || 'all');
    var userQ = userRiskQuery((document.getElementById('userRiskFilterUser') || {}).value || '');
    var srcQ = userRiskQuery((document.getElementById('userRiskFilterSource') || {}).value || '');
    var dstQ = userRiskQuery((document.getElementById('userRiskFilterDestination') || {}).value || '');
    var hoursRaw = ((document.getElementById('userRiskFilterHours') || {}).value || '').trim();
    var nowMs = Date.now();
    var maxAgeMs = 0;

    if (hoursRaw !== '') {
        var hours = parseFloat(hoursRaw);
        if (!isNaN(hours) && hours > 0) {
            maxAgeMs = hours * 3600000;
        }
    }

    var filtered = userRiskExplorerData.filter(function(row){
        if (status !== 'all' && userRiskNormalize(row.Status) !== status) return false;
        if (userQ && userRiskNormalize(row.User).indexOf(userQ) === -1) return false;

        var srcCombined = userRiskNormalize(row.SourceHost + ' ' + row.SourceIP);
        if (srcQ && srcCombined.indexOf(srcQ) === -1) return false;

        var dstCombined = userRiskNormalize(row.DestinationHost + ' ' + row.DestinationIP);
        if (dstQ && dstCombined.indexOf(dstQ) === -1) return false;

        if (maxAgeMs > 0) {
            var eventMs = Date.parse(row.TimeIso);
            if (!isNaN(eventMs) && (nowMs - eventMs) > maxAgeMs) return false;
        }

        return true;
    });

    renderUserRiskExplorer(filtered);
    renderCompoundIncidents(filtered);
}

function renderUserRiskExplorer(rows){
    var tbody = document.getElementById('userRiskActivityTbody');
    var summary = document.getElementById('userRiskFilterSummary');
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="10">No activity found for selected filters.</td></tr>';
        if (summary) { summary.innerText = '0 records listed'; }
        return;
    }

    var html = '';
    rows.forEach(function(row){
        var userSafe = userRiskEsc(row.User);
        html += '<tr>' +
            '<td>' + userRiskEsc(row.TimeDisplay) + '</td>' +
            '<td><span class="' + userRiskStatusClass(row.Status) + '">' + userRiskEsc(row.Status) + '</span></td>' +
            '<td><span class="user-risk-user-link" onclick="openUserRiskProfile(\'' + userSafe + '\')">' + userSafe + '</span></td>' +
            '<td>' + userRiskEsc(row.SourceHost) + '</td>' +
            '<td>' + userRiskEsc(row.SourceIP) + '</td>' +
            '<td>' + userRiskEsc(row.DestinationHost) + '</td>' +
            '<td>' + userRiskEsc(row.DestinationIP) + '</td>' +
            '<td>' + userRiskEsc(row.LogonType) + '</td>' +
            '<td>' + userRiskEsc(row.Reason) + '</td>' +
            '<td>' + userRiskEsc(row.SourceHost) + ' -> ' + userRiskEsc(row.DestinationHost) + '</td>' +
            '</tr>';
    });

    tbody.innerHTML = html;
    if (summary) {
        summary.innerText = rows.length + ' records listed';
    }
}

function setUserRiskQuickPreset(mode){
    resetUserRiskFilters();

    var statusEl = document.getElementById('userRiskFilterStatus');
    var hoursEl = document.getElementById('userRiskFilterHours');
    var sourceEl = document.getElementById('userRiskFilterSource');

    if (mode === 'lockout24') {
        if (statusEl) statusEl.value = 'locked';
        if (hoursEl) hoursEl.value = '24';
    } else if (mode === 'failed24') {
        if (statusEl) statusEl.value = 'failed';
        if (hoursEl) hoursEl.value = '24';
    } else if (mode === 'bruteforce') {
        if (statusEl) statusEl.value = 'failed';
        if (hoursEl) hoursEl.value = '6';
    } else if (mode === 'dcfocus') {
        if (statusEl) statusEl.value = 'all';
        if (hoursEl) hoursEl.value = '24';
        if (sourceEl) sourceEl.value = 'kbdc';
    }

    applyUserRiskFilters();
}

function renderCompoundIncidents(rows){
    var tbody = document.getElementById('userRiskIncidentTbody');
    var summary = document.getElementById('userRiskIncidentSummary');
    if (!tbody || !Array.isArray(rows)) return;

    var grouped = {};
    rows.forEach(function(r){
        var user = userRiskSafeText(r.User);
        if (!grouped[user]) {
            grouped[user] = { User: user, Failed: 0, Locked: 0, Success: 0, Sources: {}, LastTime: '-' };
        }
        var g = grouped[user];
        var s = userRiskNormalize(r.Status);
        if (s === 'failed') g.Failed += 1;
        else if (s === 'locked') g.Locked += 1;
        else if (s === 'success') g.Success += 1;

        var src = userRiskSafeText(r.SourceHost);
        if (src !== '-') g.Sources[src] = true;
        if (g.LastTime === '-' || Date.parse(r.TimeIso) > Date.parse(g.LastTimeIso || '1970-01-01')) {
            g.LastTime = userRiskSafeText(r.TimeDisplay);
            g.LastTimeIso = userRiskSafeText(r.TimeIso);
        }
    });

    var incidents = Object.keys(grouped).map(function(k){
        var g = grouped[k];
        var sourceCount = Object.keys(g.Sources).length;
        var score = (g.Failed * 2) + (g.Locked * 5) + (sourceCount >= 3 ? 3 : 0);
        return {
            User: g.User,
            Failed: g.Failed,
            Locked: g.Locked,
            Success: g.Success,
            DistinctSources: sourceCount,
            LastTime: g.LastTime,
            Score: score
        };
    }).filter(function(x){ return x.Failed > 0 || x.Locked > 0; })
      .sort(function(a,b){ return b.Score - a.Score; })
      .slice(0, 12);

    if (!incidents.length) {
        tbody.innerHTML = '<tr><td colspan="7">No compound incident candidate for selected filters.</td></tr>';
        if (summary) summary.innerText = '0 incident candidate';
        return;
    }

    var html = '';
    incidents.forEach(function(i){
        var userSafe = userRiskEsc(i.User);
        html += '<tr>' +
            '<td><span class="user-risk-user-link" onclick="openUserRiskProfile(\'' + userSafe + '\')">' + userSafe + '</span></td>' +
            '<td>' + i.Failed + '</td>' +
            '<td>' + i.Locked + '</td>' +
            '<td>' + i.Success + '</td>' +
            '<td>' + i.DistinctSources + '</td>' +
            '<td>' + userRiskEsc(i.LastTime) + '</td>' +
            '<td>' + i.Score + '</td>' +
            '</tr>';
    });

    tbody.innerHTML = html;
    if (summary) summary.innerText = incidents.length + ' incident candidate';
}

function openUserRiskProfile(userName){
    var panel = document.getElementById('userRiskProfilePanel');
    var title = document.getElementById('userRiskProfileTitle');
    var meta = document.getElementById('userRiskProfileMeta');
    var timeline = document.getElementById('userRiskProfileTimeline');
    if (!panel || !title || !meta || !timeline) return;

    var normalized = userRiskNormalize(userName);
    var rows = userRiskExplorerData.filter(function(r){ return userRiskNormalize(r.User) === normalized; });

    if (!rows.length) {
        panel.style.display = 'none';
        return;
    }

    var failed = 0, locked = 0, success = 0;
    var srcMap = {}, dstMap = {};
    var lastSeen = '-';
    var lastIso = '1970-01-01T00:00:00Z';

    rows.forEach(function(r){
        var s = userRiskNormalize(r.Status);
        if (s === 'failed') failed += 1;
        else if (s === 'locked') locked += 1;
        else if (s === 'success') success += 1;

        if (r.SourceHost && r.SourceHost !== '-') srcMap[r.SourceHost] = (srcMap[r.SourceHost] || 0) + 1;
        if (r.DestinationHost && r.DestinationHost !== '-') dstMap[r.DestinationHost] = (dstMap[r.DestinationHost] || 0) + 1;

        if (Date.parse(r.TimeIso) > Date.parse(lastIso)) {
            lastIso = r.TimeIso;
            lastSeen = r.TimeDisplay;
        }
    });

    function topKey(obj){
        var keys = Object.keys(obj);
        if (!keys.length) return '-';
        keys.sort(function(a,b){ return obj[b] - obj[a]; });
        return keys[0] + ' (' + obj[keys[0]] + ')';
    }

    title.innerText = 'User Profile: ' + userRiskSafeText(userName);
    meta.innerHTML =
        '<div><b>Failed</b><br>' + failed + '</div>' +
        '<div><b>Locked</b><br>' + locked + '</div>' +
        '<div><b>Success</b><br>' + success + '</div>' +
        '<div><b>Last Seen</b><br>' + userRiskEsc(lastSeen) + '</div>' +
        '<div><b>Top Source</b><br>' + userRiskEsc(topKey(srcMap)) + '</div>' +
        '<div><b>Top Destination</b><br>' + userRiskEsc(topKey(dstMap)) + '</div>';

    var recentRows = rows
        .slice()
        .sort(function(a,b){ return Date.parse(b.TimeIso) - Date.parse(a.TimeIso); })
        .slice(0, 20);

    if (!recentRows.length) {
        timeline.innerHTML = '<div class="user-risk-timeline-row"><div class="user-risk-timeline-time">-</div><div>-</div><div class="user-risk-timeline-path">No timeline entry</div></div>';
    } else {
        var timelineHtml = '';
        recentRows.forEach(function(r){
            timelineHtml += '<div class="user-risk-timeline-row">' +
                '<div class="user-risk-timeline-time">' + userRiskEsc(r.TimeDisplay) + '</div>' +
                '<div><span class="' + userRiskStatusClass(r.Status) + '">' + userRiskEsc(r.Status) + '</span></div>' +
                '<div class="user-risk-timeline-path">' + userRiskEsc(r.SourceHost) + ' (' + userRiskEsc(r.SourceIP) + ') -> ' + userRiskEsc(r.DestinationHost) + ' (' + userRiskEsc(r.DestinationIP) + ')</div>' +
                '</div>';
        });
        timeline.innerHTML = timelineHtml;
    }

    panel.style.display = 'block';
}

function resetUserRiskFilters(){
    var fields = ['userRiskFilterStatus', 'userRiskFilterUser', 'userRiskFilterSource', 'userRiskFilterDestination', 'userRiskFilterHours'];
    fields.forEach(function(id){
        var node = document.getElementById(id);
        if (!node) return;
        node.value = (id === 'userRiskFilterStatus') ? 'all' : '';
    });
    applyUserRiskFilters();
}

function userRiskParseDisplayDate(text){
    var value = userRiskSafeText(text).trim();
    if (value === '-' || value === '') return NaN;

    var m = value.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?$/);
    if (!m) return Date.parse(value);

    var day = parseInt(m[1], 10);
    var month = parseInt(m[2], 10) - 1;
    var year = parseInt(m[3], 10);
    var hour = m[4] ? parseInt(m[4], 10) : 0;
    var minute = m[5] ? parseInt(m[5], 10) : 0;
    var second = m[6] ? parseInt(m[6], 10) : 0;
    return new Date(year, month, day, hour, minute, second, 0).getTime();
}

function applyFailedUsersFilters(){
    var summary = document.getElementById('userRiskFailedUsersFilterSummary');
    if (!userRiskFailedUsersData || !userRiskFailedUsersData.length) {
        initUserRiskFailedDatasets();
    }

    var userQ = userRiskQuery((document.getElementById('userRiskFailedUsersFilterUser') || {}).value || '');
    var sourceQ = userRiskQuery((document.getElementById('userRiskFailedUsersFilterSource') || {}).value || '');
    var minCountRaw = ((document.getElementById('userRiskFailedUsersFilterMinCount') || {}).value || '').trim();
    var hoursRaw = ((document.getElementById('userRiskFailedUsersFilterHours') || {}).value || '').trim();

    var minCount = parseInt(minCountRaw, 10);
    if (isNaN(minCount) || minCount < 1) minCount = 0;

    var maxAgeMs = 0;
    if (hoursRaw !== '') {
        var h = parseFloat(hoursRaw);
        if (!isNaN(h) && h > 0) maxAgeMs = h * 3600000;
    }

    var nowMs = Date.now();
    var filtered = userRiskFailedUsersData.filter(function(item){
        var user = userRiskNormalize(item.TargetUser);
        var sources = userRiskNormalize(item.TopSources);
        var count = parseInt(item.FailedCount, 10);
        var lastSeenMs = Date.parse(item.LastSeenIso);
        if (isNaN(lastSeenMs)) lastSeenMs = userRiskParseDisplayDate(item.LastSeenDisplay);

        if (userQ && user.indexOf(userQ) === -1) return false;
        if (sourceQ && sources.indexOf(sourceQ) === -1) return false;
        if (minCount > 0 && (isNaN(count) || count < minCount)) return false;
        if (maxAgeMs > 0 && !isNaN(lastSeenMs) && ((nowMs - lastSeenMs) > maxAgeMs)) return false;
        return true;
    });

    renderFailedUsersRows(filtered);

    if (summary) summary.innerText = filtered.length + ' records listed';
}

function resetFailedUsersFilters(){
    showAllFailedUsers();
}

function applyFailedSourcesFilters(){
    var summary = document.getElementById('userRiskFailedSourcesFilterSummary');
    if (!userRiskFailedSourcesData || !userRiskFailedSourcesData.length) {
        initUserRiskFailedDatasets();
    }

    var sourceQ = userRiskQuery((document.getElementById('userRiskFailedSourcesFilterSource') || {}).value || '');
    var userQ = userRiskQuery((document.getElementById('userRiskFailedSourcesFilterUser') || {}).value || '');
    var minCountRaw = ((document.getElementById('userRiskFailedSourcesFilterMinCount') || {}).value || '').trim();
    var hoursRaw = ((document.getElementById('userRiskFailedSourcesFilterHours') || {}).value || '').trim();

    var minCount = parseInt(minCountRaw, 10);
    if (isNaN(minCount) || minCount < 1) minCount = 0;

    var maxAgeMs = 0;
    if (hoursRaw !== '') {
        var h = parseFloat(hoursRaw);
        if (!isNaN(h) && h > 0) maxAgeMs = h * 3600000;
    }

    var nowMs = Date.now();
    var filtered = userRiskFailedSourcesData.filter(function(item){
        var source = userRiskNormalize(item.Source);
        var users = userRiskNormalize(item.TopUsers);
        var count = parseInt(item.FailedCount, 10);
        var lastSeenMs = Date.parse(item.LastSeenIso);
        if (isNaN(lastSeenMs)) lastSeenMs = userRiskParseDisplayDate(item.LastSeenDisplay);

        if (sourceQ && source.indexOf(sourceQ) === -1) return false;
        if (userQ && users.indexOf(userQ) === -1) return false;
        if (minCount > 0 && (isNaN(count) || count < minCount)) return false;
        if (maxAgeMs > 0 && !isNaN(lastSeenMs) && ((nowMs - lastSeenMs) > maxAgeMs)) return false;
        return true;
    });

    renderFailedSourcesRows(filtered);

    if (summary) summary.innerText = filtered.length + ' records listed';
}

function resetFailedSourcesFilters(){
    showAllFailedSources();
}

function hideAllContainers(){
    var containers=document.getElementsByClassName('container');
    for(var i=0;i<containers.length;i++){
        containers[i].style.display='none';
    }
} 
// LOADING OVERLAY FUNCTION
function showLoadingAndContent(id){
    var overlay = document.getElementById('loadingOverlay');
    
    // 1. Make overlay visible immediately (display: flex)
    overlay.style.display = 'flex';
    
    // 2. After a short delay (to let browser detect display change), set opacity to 1
    setTimeout(function() {
        overlay.classList.add('visible'); // sets opacity: 1, starts fade-in (300ms)
    }, 10);
    
    // 3. Hide current content
    hideAllContainers();
    
    // 4. After animation and display time completes (400ms = 10ms + 300ms fade-in + wait)
    setTimeout(function() {
        // Show new content
        var newContainer = document.getElementById(id);
        if(newContainer) {
            newContainer.style.display = 'flex';
            currentContainerId = id;
        }
        if (id === 'ouTreeContainer') { setTimeout(initOUTree, 100); }
        
        // Start hiding loading overlay (set opacity: 0, start fade-out)
        overlay.classList.remove('visible');
        
        // 5. Fade-out animasyonu bittikten sonra (300ms) display: none yap
        setTimeout(function() {
            overlay.style.display = 'none'; 
        }, 300); 

        updateHashFromState();
        
    }, 400); 
}

function toggleSubMenu(menuId, targetId){
    var menu = document.getElementById(menuId);
    if (menu.style.display === 'flex') {
        menu.style.display = 'none';
    } else {
        // Hide all submenus
        var subMenus = document.getElementsByClassName('sub-buttons');
        for (var i = 0; i < subMenus.length; i++) {
            if (subMenus[i].id !== menuId) {
                subMenus[i].style.display = 'none';
            }
        }
        menu.style.display = 'flex';
        // Load default sub-container when submenu opens
        if (targetId) {
            showLoadingAndContent(targetId); 
        }
    }
}

document.addEventListener('DOMContentLoaded', function(){
    var mainButtons = document.querySelectorAll('.side-menu .main-btn');
    for (var i = 0; i < mainButtons.length; i++) {
        mainButtons[i].addEventListener('click', function(){
            for (var j = 0; j < mainButtons.length; j++) {
                mainButtons[j].classList.remove('active-sidebar');
            }
            this.classList.add('active-sidebar');
        });
    }
    var anyVisible = document.querySelector('.container[style*="display: flex"], .container[style*="display:flex"]');
    if (!anyVisible) {
        var fallbackContainer = document.getElementById('pingCastleRisksContainer');
        if (fallbackContainer) {
            fallbackContainer.style.display = 'flex';
            currentContainerId = 'pingCastleRisksContainer';
        }
    }
});

function resolveLogoPath(){
    var logoCandidates = ['tools/kuso_logo.png', 'kuso_logo.png', '../tools/kuso_logo.png'];
    var headerLogo = document.getElementById('headerLogo');
    var loadingLogo = document.querySelector('.loading-logo');

    function tryNext(index){
        if (index >= logoCandidates.length) {
            if (headerLogo) headerLogo.style.display = 'none';
            if (loadingLogo) loadingLogo.style.display = 'none';
            return;
        }

        var probe = new Image();
        probe.onload = function(){
            var selected = logoCandidates[index];
            if (headerLogo) headerLogo.src = selected;
            if (loadingLogo) loadingLogo.style.backgroundImage = "url('" + selected + "')";
        };
        probe.onerror = function(){
            tryNext(index + 1);
        };
        probe.src = logoCandidates[index];
    }

    tryNext(0);
}

function fitSidebarToViewport(){
    var sideMenu = document.querySelector('.side-menu');
    if (!sideMenu) return;

    if (window.innerWidth <= 900) {
        sideMenu.style.maxHeight = 'none';
        return;
    }

    var rect = sideMenu.getBoundingClientRect();
    var marginBottom = 12;
    var available = Math.floor(window.innerHeight - rect.top - marginBottom);
    if (available < 260) available = 260;
    sideMenu.style.maxHeight = available + 'px';
}
// Show first tab at startup
window.onload = function() {
    document.body.classList.add('sneat-cyber');
    document.body.classList.add('compact-mode');

    // Fail-safe: always show a default container first.
    try {
        var landing = document.getElementById('pingCastleRisksContainer');
        if (landing) {
            landing.style.display = 'flex';
            currentContainerId = 'pingCastleRisksContainer';
        }
    } catch (e) {
        console.error('Landing container init error:', e);
    }

    function safeInit(fn){
        try { fn(); } catch (e) { console.error('Init step failed:', e); }
    }

    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: true, securityLevel: 'loose' });
    }

    safeInit(resolveLogoPath);
    safeInit(fitSidebarToViewport);
    safeInit(addExportButtonsToTables);
    safeInit(applyDefaultNetworkOrdering);
    safeInit(initUserRiskExplorer);
    safeInit(buildAttackChainGraph);
    safeInit(renderMitreHeatmap);
    safeInit(renderThreatPriorityQueue);
    safeInit(renderCaRiskLens);
    safeInit(initRemediationTracking);
    safeInit(initChangeApprovalGate);
    safeInit(function(){ applyPingRiskFocus('all'); });
    safeInit(renderRiskImpactSimulator);
    safeInit(renderRiskContributionBreakdown);
    safeInit(initRiskWatchlist);
    safeInit(renderDcHealthHeatmap);

    var state = readHashState();
    var storedLang = 'en';
    try { storedLang = localStorage.getItem('adcheck-lang') || 'en'; } catch (e) {}

window.addEventListener('resize', fitSidebarToViewport);
    if (state) {
        if (state.c && document.getElementById(state.c)) {
            hideAllContainers();
            document.getElementById(state.c).style.display = 'flex';
            currentContainerId = state.c;
        }
        if (state.rf) applyPingRiskFocus(state.rf);
        if (state.tf) filterRemediationStatus(state.tf);
        if (state.lg) storedLang = state.lg;
    }
    applyLanguage(storedLang);
    updateHashFromState();
};
