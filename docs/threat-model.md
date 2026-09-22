# Threat Model

Detections in this project are scoped to the techniques below, chosen for realistic
relevance to a small/mid-size AWS environment and mapped to MITRE ATT&CK (Cloud/IaaS matrix).

| # | Technique | ATT&CK ID | Primary CloudTrail Event(s) | Why it's in scope |
|---|---|---|---|---|
| 1 | Disable CloudTrail logging | T1562.008 | `StopLogging`, `UpdateTrail`, `DeleteTrail` | Classic first move after compromise — attacker blinds defenders |
| 2 | Disable GuardDuty | T1562.001 | `UpdateDetector` (status=DISABLED), `DeleteDetector` | Same intent as #1, targets the managed detection layer directly |
| 3 | Delete CloudWatch log group | T1070.002 | `DeleteLogGroup` | Removes evidence after the fact |
| 4 | Root account activity | T1078.004 | any event where `userIdentity.type == Root` | Root should almost never be used day-to-day; high-signal on its own |
| 5 | Console login without MFA | T1078.004 | `ConsoleLogin` (`additionalEventData.MFAUsed == No`) | Direct policy violation, precursor to credential-based access |
| 6 | Failed logins followed by success | T1110 | `ConsoleLogin` (multiple `Failure` then `Success`) | Password-guessing pattern |
| 7 | New access key created for another user | T1098.001 | `CreateAccessKey` (actor != target user) | Common persistence move after gaining IAM access |
| 8 | New IAM user created and given admin | T1136.001 + T1098.001 | `CreateUser` → `AttachUserPolicy` (AdministratorAccess) | Attacker creates their own persistent foothold |
| 9 | Admin policy attached to existing user/role | T1098.001 | `AttachUserPolicy`/`PutUserPolicy` (Administrator­Access or `*:*`) | Direct privilege escalation, closes gap noted in scanner project |
| 10 | Login profile created for existing IAM user | T1098.001 | `CreateLoginProfile` | Gives console access to a user that previously had none (e.g. a service account) |
| 11 | IAM role trust policy modified | T1098.003 | `UpdateAssumeRolePolicy` | Attacker adds themselves/another account as a trusted principal |
| 12 | `iam:PassRole` + Lambda/EC2 creation | T1548.005 | `CreateFunction`/`RunInstances` following a `PassRole` call with a high-privilege role | Known privilege-escalation chain; needs correlation, not a single event |
| 13 | Unusual `Get`/`List`/`Describe` volume from one identity | T1580 | high-frequency read-only calls in a short window | Recon behaviour after initial access |
| 14 | Secrets Manager value accessed at volume | T1552.001 | `GetSecretValue` (spike per identity) | Credential harvesting |
| 15 | S3 bucket policy made public | T1530 | `PutBucketPolicy`/`PutBucketAcl` (Principal `*`) | Overlaps with scanner's static check — this is the *event*, not just the resulting state |
| 16 | Public S3 object accessed at volume after policy change | T1530 | `GetObject` spike following #15 | Confirms actual exfiltration, not just exposure |
| 17 | EC2 snapshot shared to external account | T1537 | `ModifySnapshotAttribute` (add account to `createVolumePermission`) | Common data-exfil path via full disk snapshot |
| 18 | Security group opened to 0.0.0.0/0 | T1190 | `AuthorizeSecurityGroupIngress` (CidrIp 0.0.0.0/0) | Same misconfig scanner catches statically; this is the live event |
| 19 | VPC flow logs disabled/deleted | T1562.008 | `DeleteFlowLogs` | Removes network-level visibility |
| 20 | Console login from new geography/ASN | T1078.004 | `ConsoleLogin` (IP/geo not seen for this identity before) | Requires a baseline — good stretch goal, flag as "phase 2" if too complex for now |
