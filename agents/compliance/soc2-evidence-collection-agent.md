# SOC2 Evidence Collection Agent

## Overview
This agent specializes in automated evidence collection, organization, and management for SOC2 Type 2 audits, ensuring continuous compliance monitoring and audit-ready documentation.

## Capabilities

### Evidence Collection
- Automated evidence gathering
- Multi-source integration
- Real-time collection
- Historical data retrieval
- Evidence validation
- Chain of custody maintenance

### Evidence Types
- System configurations
- Access logs and reports
- Change management records
- Security scan results
- Policy documents
- Training records
- Incident reports
- Vendor assessments

### Storage and Organization
- Centralized evidence repository
- Automated categorization
- Version control
- Retention management
- Access controls
- Audit trails

## Automated Evidence Collection Framework

### Evidence Collection Architecture
```python
import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import boto3
import aiohttp
from cryptography.fernet import Fernet

class EvidenceType(Enum):
    CONFIGURATION = "configuration"
    LOG = "log"
    REPORT = "report"
    SCREENSHOT = "screenshot"
    DOCUMENT = "document"
    SCAN_RESULT = "scan_result"
    METRIC = "metric"
    ATTESTATION = "attestation"

@dataclass
class Evidence:
    evidence_id: str
    control_id: str
    evidence_type: EvidenceType
    title: str
    description: str
    collection_date: datetime
    period_start: datetime
    period_end: datetime
    source_system: str
    collector: str
    data: Dict[str, Any]
    hash: str
    metadata: Dict[str, Any]
    
class EvidenceCollectionFramework:
    def __init__(self, config: Dict):
        self.config = config
        self.collectors = self._initialize_collectors()
        self.storage = EvidenceStorage(config['storage'])
        self.validator = EvidenceValidator()
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        
    def _initialize_collectors(self) -> Dict:
        """Initialize all evidence collectors"""
        return {
            'aws': AWSEvidenceCollector(self.config['aws']),
            'azure': AzureEvidenceCollector(self.config['azure']),
            'github': GitHubEvidenceCollector(self.config['github']),
            'okta': OktaEvidenceCollector(self.config['okta']),
            'jira': JiraEvidenceCollector(self.config['jira']),
            'datadog': DatadogEvidenceCollector(self.config['datadog']),
            'databases': DatabaseEvidenceCollector(self.config['databases']),
            'applications': ApplicationEvidenceCollector(self.config['applications'])
        }
    
    async def collect_all_evidence(self, controls: List[str] = None) -> List[Evidence]:
        """Collect evidence for all or specified controls"""
        tasks = []
        
        # Create collection tasks for each control
        control_mappings = self._get_control_mappings()
        
        for control_id, collectors in control_mappings.items():
            if controls and control_id not in controls:
                continue
                
            for collector_name in collectors:
                if collector_name in self.collectors:
                    task = self._collect_control_evidence(
                        control_id, 
                        self.collectors[collector_name]
                    )
                    tasks.append(task)
        
        # Execute all collections in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        all_evidence = []
        for result in results:
            if isinstance(result, Exception):
                self._log_collection_error(result)
            else:
                all_evidence.extend(result)
        
        return all_evidence
    
    async def _collect_control_evidence(self, control_id: str, 
                                      collector: 'BaseEvidenceCollector') -> List[Evidence]:
        """Collect evidence for a specific control"""
        try:
            raw_evidence = await collector.collect(control_id)
            
            evidence_list = []
            for item in raw_evidence:
                # Create evidence object
                evidence = Evidence(
                    evidence_id=self._generate_evidence_id(),
                    control_id=control_id,
                    evidence_type=item['type'],
                    title=item['title'],
                    description=item['description'],
                    collection_date=datetime.utcnow(),
                    period_start=item.get('period_start', datetime.utcnow() - timedelta(days=1)),
                    period_end=item.get('period_end', datetime.utcnow()),
                    source_system=collector.source_system,
                    collector=collector.__class__.__name__,
                    data=item['data'],
                    hash=self._calculate_hash(item['data']),
                    metadata=item.get('metadata', {})
                )
                
                # Validate evidence
                if self.validator.validate(evidence):
                    # Encrypt sensitive data
                    evidence = self._encrypt_sensitive_data(evidence)
                    
                    # Store evidence
                    await self.storage.store(evidence)
                    
                    evidence_list.append(evidence)
                else:
                    self._log_validation_failure(evidence)
            
            return evidence_list
            
        except Exception as e:
            self._log_collection_error(e, control_id, collector.source_system)
            return []
    
    def _calculate_hash(self, data: Dict) -> str:
        """Calculate SHA-256 hash of evidence data"""
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def _encrypt_sensitive_data(self, evidence: Evidence) -> Evidence:
        """Encrypt sensitive fields in evidence"""
        sensitive_fields = ['credentials', 'api_keys', 'passwords', 'ssn', 'credit_card']
        
        for field in sensitive_fields:
            if field in evidence.data:
                encrypted_value = self.fernet.encrypt(
                    json.dumps(evidence.data[field]).encode()
                )
                evidence.data[field] = encrypted_value.decode()
                evidence.metadata['encrypted_fields'] = evidence.metadata.get('encrypted_fields', [])
                evidence.metadata['encrypted_fields'].append(field)
        
        return evidence
    
    def _get_control_mappings(self) -> Dict[str, List[str]]:
        """Map controls to evidence collectors"""
        return {
            'CC1.1': ['okta', 'github', 'jira'],  # Control Environment
            'CC1.2': ['okta', 'applications'],     # Board Independence
            'CC2.1': ['datadog', 'applications'],  # Communication
            'CC2.2': ['jira', 'github'],           # Internal Communication
            'CC3.1': ['jira', 'applications'],     # Risk Assessment
            'CC3.2': ['aws', 'azure', 'datadog'],  # Risk Identification
            'CC4.1': ['datadog', 'applications'],  # Monitoring
            'CC4.2': ['datadog', 'aws'],          # Performance Monitoring
            'CC5.1': ['github', 'jira'],          # Control Activities
            'CC5.2': ['aws', 'azure'],            # Technology Controls
            'CC6.1': ['okta', 'aws', 'azure'],   # Logical Access
            'CC6.2': ['okta', 'databases'],       # New User Access
            'CC6.3': ['okta', 'applications'],    # User Access Removal
            'CC6.4': ['okta', 'aws'],            # Access Reviews
            'CC6.5': ['applications', 'databases'], # Segregation of Duties
            'CC6.6': ['aws', 'azure', 'datadog'], # Physical Security
            'CC6.7': ['aws', 'azure', 'databases'], # Data Transmission
            'CC6.8': ['aws', 'azure'],            # Malicious Software
            'CC7.1': ['datadog', 'aws', 'azure'], # Detection
            'CC7.2': ['datadog', 'applications'],  # Monitoring
            'CC7.3': ['jira', 'datadog'],         # Incident Response
            'CC7.4': ['jira', 'github'],          # Incident Analysis
            'CC8.1': ['github', 'jira'],          # Change Management
            'CC9.1': ['jira', 'applications'],     # Risk Mitigation
            'CC9.2': ['aws', 'azure', 'applications'], # Vendor Management
            'A1.1': ['datadog', 'aws', 'azure'],  # Availability
            'A1.2': ['aws', 'azure'],             # Capacity Planning
            'A1.3': ['datadog', 'applications'],   # Performance
            'C1.1': ['applications', 'databases'],  # Confidentiality
            'C1.2': ['aws', 'azure', 'databases'], # Data Disposal
            'PI1.1': ['applications', 'databases'], # Processing Integrity
            'PI1.2': ['datadog', 'applications'],  # Data Validation
            'P1.1': ['applications', 'okta'],      # Privacy Notice
            'P2.1': ['applications', 'databases'],  # Data Collection
            'P3.1': ['applications', 'okta'],      # Data Use
            'P4.1': ['applications', 'databases'],  # Data Access
            'P5.1': ['applications', 'jira'],      # Data Disclosure
            'P6.1': ['applications', 'databases'],  # Data Quality
            'P7.1': ['applications', 'databases'],  # Data Retention
            'P8.1': ['applications', 'databases']   # Data Disposal
        }

class AWSEvidenceCollector:
    def __init__(self, config: Dict):
        self.config = config
        self.source_system = 'AWS'
        self.clients = self._initialize_clients()
    
    def _initialize_clients(self) -> Dict:
        """Initialize AWS SDK clients"""
        session = boto3.Session(
            aws_access_key_id=self.config['access_key'],
            aws_secret_access_key=self.config['secret_key'],
            region_name=self.config['region']
        )
        
        return {
            'iam': session.client('iam'),
            'cloudtrail': session.client('cloudtrail'),
            'config': session.client('config'),
            'guardduty': session.client('guardduty'),
            'securityhub': session.client('securityhub'),
            's3': session.client('s3'),
            'ec2': session.client('ec2'),
            'cloudwatch': session.client('cloudwatch'),
            'kms': session.client('kms'),
            'rds': session.client('rds')
        }
    
    async def collect(self, control_id: str) -> List[Dict]:
        """Collect AWS evidence for specific control"""
        evidence = []
        
        # Control-specific collection logic
        if control_id == 'CC6.1':  # Logical Access
            evidence.extend(await self._collect_iam_evidence())
            evidence.extend(await self._collect_mfa_evidence())
            
        elif control_id == 'CC6.4':  # Access Reviews
            evidence.extend(await self._collect_access_review_evidence())
            
        elif control_id == 'CC6.6':  # Network Security
            evidence.extend(await self._collect_network_security_evidence())
            
        elif control_id == 'CC6.7':  # Encryption
            evidence.extend(await self._collect_encryption_evidence())
            
        elif control_id == 'CC7.1':  # Detection
            evidence.extend(await self._collect_detection_evidence())
            
        elif control_id == 'CC7.2':  # Monitoring
            evidence.extend(await self._collect_monitoring_evidence())
            
        elif control_id == 'A1.1':  # Availability
            evidence.extend(await self._collect_availability_evidence())
        
        return evidence
    
    async def _collect_iam_evidence(self) -> List[Dict]:
        """Collect IAM configuration evidence"""
        evidence = []
        
        # Password policy
        try:
            password_policy = self.clients['iam'].get_account_password_policy()
            evidence.append({
                'type': EvidenceType.CONFIGURATION,
                'title': 'AWS IAM Password Policy',
                'description': 'Current IAM password policy configuration',
                'data': password_policy['PasswordPolicy'],
                'metadata': {
                    'compliant': self._check_password_policy_compliance(
                        password_policy['PasswordPolicy']
                    )
                }
            })
        except self.clients['iam'].exceptions.NoSuchEntityException:
            evidence.append({
                'type': EvidenceType.CONFIGURATION,
                'title': 'AWS IAM Password Policy',
                'description': 'No password policy configured',
                'data': {'status': 'not_configured'},
                'metadata': {'compliant': False}
            })
        
        # IAM users report
        users = self.clients['iam'].list_users()
        user_details = []
        
        for user in users['Users']:
            # Get user details
            access_keys = self.clients['iam'].list_access_keys(
                UserName=user['UserName']
            )
            mfa_devices = self.clients['iam'].list_mfa_devices(
                UserName=user['UserName']
            )
            groups = self.clients['iam'].list_groups_for_user(
                UserName=user['UserName']
            )
            
            user_details.append({
                'UserName': user['UserName'],
                'CreateDate': user['CreateDate'].isoformat(),
                'PasswordLastUsed': user.get('PasswordLastUsed', 'Never').isoformat() 
                    if isinstance(user.get('PasswordLastUsed'), datetime) else 'Never',
                'AccessKeys': len(access_keys['AccessKeyMetadata']),
                'MFAEnabled': len(mfa_devices['MFADevices']) > 0,
                'Groups': [g['GroupName'] for g in groups['Groups']]
            })
        
        evidence.append({
            'type': EvidenceType.REPORT,
            'title': 'AWS IAM Users Report',
            'description': 'List of all IAM users with security status',
            'data': {
                'users': user_details,
                'total_users': len(user_details),
                'users_without_mfa': len([u for u in user_details if not u['MFAEnabled']])
            }
        })
        
        return evidence
    
    async def _collect_mfa_evidence(self) -> List[Dict]:
        """Collect MFA enforcement evidence"""
        evidence = []
        
        # Get virtual MFA devices
        virtual_mfa = self.clients['iam'].list_virtual_mfa_devices()
        
        evidence.append({
            'type': EvidenceType.REPORT,
            'title': 'AWS MFA Device Report',
            'description': 'List of all MFA devices',
            'data': {
                'virtual_mfa_devices': len(virtual_mfa['VirtualMFADevices']),
                'devices': [
                    {
                        'SerialNumber': device['SerialNumber'],
                        'User': device.get('User', {}).get('UserName', 'Unassigned'),
                        'EnableDate': device.get('EnableDate', '').isoformat() 
                            if device.get('EnableDate') else 'Not enabled'
                    }
                    for device in virtual_mfa['VirtualMFADevices']
                ]
            }
        })
        
        return evidence
    
    async def _collect_network_security_evidence(self) -> List[Dict]:
        """Collect network security configuration evidence"""
        evidence = []
        
        # Security groups
        security_groups = self.clients['ec2'].describe_security_groups()
        
        risky_rules = []
        for sg in security_groups['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                # Check for overly permissive rules
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        risky_rules.append({
                            'SecurityGroupId': sg['GroupId'],
                            'GroupName': sg['GroupName'],
                            'Protocol': rule.get('IpProtocol', 'all'),
                            'FromPort': rule.get('FromPort', 'all'),
                            'ToPort': rule.get('ToPort', 'all'),
                            'Source': '0.0.0.0/0'
                        })
        
        evidence.append({
            'type': EvidenceType.CONFIGURATION,
            'title': 'AWS Security Groups Configuration',
            'description': 'Security group rules and compliance status',
            'data': {
                'total_security_groups': len(security_groups['SecurityGroups']),
                'risky_rules': risky_rules,
                'compliant': len(risky_rules) == 0
            }
        })
        
        # VPC Flow Logs
        vpcs = self.clients['ec2'].describe_vpcs()
        flow_logs = self.clients['ec2'].describe_flow_logs()
        
        vpcs_with_flow_logs = set(
            fl['ResourceId'] for fl in flow_logs['FlowLogs']
        )
        vpcs_without_flow_logs = [
            vpc['VpcId'] for vpc in vpcs['Vpcs'] 
            if vpc['VpcId'] not in vpcs_with_flow_logs
        ]
        
        evidence.append({
            'type': EvidenceType.CONFIGURATION,
            'title': 'VPC Flow Logs Status',
            'description': 'VPC flow logs configuration for network monitoring',
            'data': {
                'total_vpcs': len(vpcs['Vpcs']),
                'vpcs_with_flow_logs': len(vpcs_with_flow_logs),
                'vpcs_without_flow_logs': vpcs_without_flow_logs,
                'compliant': len(vpcs_without_flow_logs) == 0
            }
        })
        
        return evidence
    
    async def _collect_encryption_evidence(self) -> List[Dict]:
        """Collect encryption configuration evidence"""
        evidence = []
        
        # S3 bucket encryption
        s3_buckets = self.clients['s3'].list_buckets()
        
        bucket_encryption_status = []
        for bucket in s3_buckets['Buckets']:
            try:
                encryption = self.clients['s3'].get_bucket_encryption(
                    Bucket=bucket['Name']
                )
                bucket_encryption_status.append({
                    'BucketName': bucket['Name'],
                    'EncryptionEnabled': True,
                    'EncryptionType': encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                })
            except self.clients['s3'].exceptions.ServerSideEncryptionConfigurationNotFoundError:
                bucket_encryption_status.append({
                    'BucketName': bucket['Name'],
                    'EncryptionEnabled': False,
                    'EncryptionType': 'None'
                })
        
        evidence.append({
            'type': EvidenceType.CONFIGURATION,
            'title': 'S3 Bucket Encryption Status',
            'description': 'Encryption configuration for all S3 buckets',
            'data': {
                'buckets': bucket_encryption_status,
                'total_buckets': len(bucket_encryption_status),
                'encrypted_buckets': len([b for b in bucket_encryption_status if b['EncryptionEnabled']]),
                'compliant': all(b['EncryptionEnabled'] for b in bucket_encryption_status)
            }
        })
        
        # RDS encryption
        rds_instances = self.clients['rds'].describe_db_instances()
        
        rds_encryption_status = []
        for instance in rds_instances['DBInstances']:
            rds_encryption_status.append({
                'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                'StorageEncrypted': instance.get('StorageEncrypted', False),
                'KmsKeyId': instance.get('KmsKeyId', 'Not encrypted')
            })
        
        evidence.append({
            'type': EvidenceType.CONFIGURATION,
            'title': 'RDS Encryption Status',
            'description': 'Encryption configuration for RDS instances',
            'data': {
                'instances': rds_encryption_status,
                'total_instances': len(rds_encryption_status),
                'encrypted_instances': len([i for i in rds_encryption_status if i['StorageEncrypted']]),
                'compliant': all(i['StorageEncrypted'] for i in rds_encryption_status)
            }
        })
        
        return evidence
    
    async def _collect_detection_evidence(self) -> List[Dict]:
        """Collect security detection evidence"""
        evidence = []
        
        # GuardDuty findings
        try:
            detectors = self.clients['guardduty'].list_detectors()
            
            if detectors['DetectorIds']:
                detector_id = detectors['DetectorIds'][0]
                
                # Get recent findings
                findings = self.clients['guardduty'].list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'createdAt': {
                                'GreaterThanOrEqual': 
                                    int((datetime.utcnow() - timedelta(days=7)).timestamp() * 1000)
                            }
                        }
                    }
                )
                
                # Get finding details
                if findings['FindingIds']:
                    finding_details = self.clients['guardduty'].get_findings(
                        DetectorId=detector_id,
                        FindingIds=findings['FindingIds'][:10]  # Limit to 10 most recent
                    )
                    
                    evidence.append({
                        'type': EvidenceType.REPORT,
                        'title': 'GuardDuty Security Findings',
                        'description': 'Recent security findings from AWS GuardDuty',
                        'data': {
                            'total_findings': len(findings['FindingIds']),
                            'sample_findings': [
                                {
                                    'Title': f['Title'],
                                    'Severity': f['Severity'],
                                    'Type': f['Type'],
                                    'CreatedAt': f['CreatedAt']
                                }
                                for f in finding_details['Findings']
                            ]
                        }
                    })
                else:
                    evidence.append({
                        'type': EvidenceType.REPORT,
                        'title': 'GuardDuty Security Findings',
                        'description': 'No recent security findings',
                        'data': {
                            'total_findings': 0,
                            'sample_findings': []
                        }
                    })
        except Exception as e:
            evidence.append({
                'type': EvidenceType.REPORT,
                'title': 'GuardDuty Status',
                'description': 'GuardDuty service status',
                'data': {
                    'enabled': False,
                    'error': str(e)
                }
            })
        
        # Security Hub findings
        try:
            hub_findings = self.clients['securityhub'].get_findings(
                Filters={
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                },
                MaxResults=20
            )
            
            evidence.append({
                'type': EvidenceType.REPORT,
                'title': 'Security Hub Findings',
                'description': 'Active security findings from AWS Security Hub',
                'data': {
                    'total_findings': len(hub_findings['Findings']),
                    'findings_by_severity': self._group_findings_by_severity(hub_findings['Findings']),
                    'findings_by_type': self._group_findings_by_type(hub_findings['Findings'])
                }
            })
        except Exception as e:
            evidence.append({
                'type': EvidenceType.REPORT,
                'title': 'Security Hub Status',
                'description': 'Security Hub service status',
                'data': {
                    'enabled': False,
                    'error': str(e)
                }
            })
        
        return evidence
    
    def _check_password_policy_compliance(self, policy: Dict) -> bool:
        """Check if password policy meets SOC2 requirements"""
        required_settings = {
            'MinimumPasswordLength': 12,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'MaxPasswordAge': 90,
            'PasswordReusePrevention': 12
        }
        
        for setting, required_value in required_settings.items():
            if setting not in policy:
                return False
            
            if isinstance(required_value, bool):
                if policy[setting] != required_value:
                    return False
            elif isinstance(required_value, int):
                if setting == 'MaxPasswordAge':
                    if policy.get(setting, 0) == 0 or policy.get(setting, 999) > required_value:
                        return False
                elif policy.get(setting, 0) < required_value:
                    return False
        
        return True
    
    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict:
        """Group security findings by severity"""
        severity_groups = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        }
        
        for finding in findings:
            severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
            if severity in severity_groups:
                severity_groups[severity] += 1
        
        return severity_groups
    
    def _group_findings_by_type(self, findings: List[Dict]) -> Dict:
        """Group security findings by type"""
        type_groups = {}
        
        for finding in findings:
            finding_type = finding.get('Types', ['Unknown'])[0].split('/')[-1]
            type_groups[finding_type] = type_groups.get(finding_type, 0) + 1
        
        return type_groups
```

### Evidence Storage and Management
```python
class EvidenceStorage:
    def __init__(self, config: Dict):
        self.config = config
        self.storage_backend = self._initialize_storage()
        self.metadata_db = self._initialize_metadata_db()
    
    def _initialize_storage(self):
        """Initialize storage backend (S3, Azure Blob, etc.)"""
        if self.config['type'] == 's3':
            return S3Storage(self.config['s3'])
        elif self.config['type'] == 'azure_blob':
            return AzureBlobStorage(self.config['azure_blob'])
        elif self.config['type'] == 'gcs':
            return GCSStorage(self.config['gcs'])
        else:
            return LocalStorage(self.config['local'])
    
    async def store(self, evidence: Evidence) -> str:
        """Store evidence with metadata"""
        # Generate storage path
        path = self._generate_storage_path(evidence)
        
        # Serialize evidence
        evidence_data = {
            'evidence': evidence.__dict__,
            'storage_metadata': {
                'stored_at': datetime.utcnow().isoformat(),
                'stored_by': 'automated_collector',
                'storage_path': path,
                'retention_period': self._get_retention_period(evidence.control_id)
            }
        }
        
        # Store in backend
        storage_url = await self.storage_backend.store(
            path, 
            json.dumps(evidence_data, default=str).encode()
        )
        
        # Store metadata in database
        await self._store_metadata(evidence, storage_url)
        
        # Create audit log entry
        await self._create_audit_log(evidence, 'stored', storage_url)
        
        return storage_url
    
    def _generate_storage_path(self, evidence: Evidence) -> str:
        """Generate hierarchical storage path"""
        date = evidence.collection_date
        
        return (
            f"soc2-evidence/"
            f"year={date.year}/"
            f"month={date.month:02d}/"
            f"day={date.day:02d}/"
            f"control={evidence.control_id}/"
            f"type={evidence.evidence_type.value}/"
            f"{evidence.evidence_id}.json"
        )
    
    async def _store_metadata(self, evidence: Evidence, storage_url: str):
        """Store evidence metadata in database"""
        metadata_record = {
            'evidence_id': evidence.evidence_id,
            'control_id': evidence.control_id,
            'evidence_type': evidence.evidence_type.value,
            'title': evidence.title,
            'collection_date': evidence.collection_date,
            'period_start': evidence.period_start,
            'period_end': evidence.period_end,
            'source_system': evidence.source_system,
            'storage_url': storage_url,
            'hash': evidence.hash,
            'metadata': evidence.metadata,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(
                days=self._get_retention_period(evidence.control_id)
            )
        }
        
        await self.metadata_db.insert('evidence_metadata', metadata_record)
        
        # Create indexes for efficient querying
        await self.metadata_db.create_index('evidence_metadata', ['control_id', 'collection_date'])
        await self.metadata_db.create_index('evidence_metadata', ['evidence_type', 'period_start'])
    
    async def retrieve(self, evidence_id: str) -> Evidence:
        """Retrieve evidence by ID"""
        # Get metadata
        metadata = await self.metadata_db.find_one(
            'evidence_metadata',
            {'evidence_id': evidence_id}
        )
        
        if not metadata:
            raise ValueError(f"Evidence {evidence_id} not found")
        
        # Retrieve from storage
        evidence_data = await self.storage_backend.retrieve(metadata['storage_url'])
        
        # Deserialize and verify
        data = json.loads(evidence_data)
        evidence_dict = data['evidence']
        
        # Verify hash
        if self._calculate_hash(evidence_dict['data']) != evidence_dict['hash']:
            raise ValueError(f"Evidence {evidence_id} integrity check failed")
        
        # Create audit log entry
        await self._create_audit_log(
            Evidence(**evidence_dict), 
            'retrieved',
            metadata['storage_url']
        )
        
        return Evidence(**evidence_dict)
    
    async def search(self, criteria: Dict) -> List[Evidence]:
        """Search for evidence based on criteria"""
        # Build query
        query = {}
        
        if 'control_id' in criteria:
            query['control_id'] = criteria['control_id']
        
        if 'date_range' in criteria:
            query['collection_date'] = {
                '$gte': criteria['date_range']['start'],
                '$lte': criteria['date_range']['end']
            }
        
        if 'evidence_type' in criteria:
            query['evidence_type'] = criteria['evidence_type']
        
        if 'source_system' in criteria:
            query['source_system'] = criteria['source_system']
        
        # Execute search
        results = await self.metadata_db.find('evidence_metadata', query)
        
        # Retrieve evidence objects
        evidence_list = []
        for result in results:
            try:
                evidence = await self.retrieve(result['evidence_id'])
                evidence_list.append(evidence)
            except Exception as e:
                self._log_retrieval_error(result['evidence_id'], e)
        
        return evidence_list
    
    def _get_retention_period(self, control_id: str) -> int:
        """Get retention period in days for control"""
        # SOC2 typically requires 1 year of evidence
        # Some controls may require longer retention
        retention_map = {
            'default': 365,
            'financial': 2555,  # 7 years for financial controls
            'hr': 1095,  # 3 years for HR-related controls
            'security_incidents': 1095  # 3 years for security incidents
        }
        
        # Map controls to categories
        if control_id in ['CC9.1', 'PI1.1']:
            return retention_map['financial']
        elif control_id in ['CC1.1', 'CC1.2']:
            return retention_map['hr']
        elif control_id in ['CC7.3', 'CC7.4']:
            return retention_map['security_incidents']
        else:
            return retention_map['default']
```

### Evidence Collection Scheduling
```yaml
# Evidence collection schedule configuration
name: SOC2 Evidence Collection Schedule
version: 1.0

schedules:
  - name: Daily Evidence Collection
    frequency: "0 2 * * *"  # 2 AM daily
    controls:
      - CC6.1  # Access logs
      - CC6.3  # User deprovisioning
      - CC7.1  # Security monitoring
      - CC7.2  # System monitoring
      - A1.1   # Availability metrics
    collectors:
      - aws
      - azure
      - okta
      - datadog
    
  - name: Weekly Evidence Collection
    frequency: "0 3 * * 1"  # 3 AM every Monday
    controls:
      - CC6.4  # Access reviews
      - CC8.1  # Change management
      - CC9.2  # Vendor assessments
    collectors:
      - github
      - jira
      - applications
    
  - name: Monthly Evidence Collection
    frequency: "0 4 1 * *"  # 4 AM first day of month
    controls:
      - CC1.1  # Policy reviews
      - CC3.1  # Risk assessments
      - CC5.1  # Control testing
    collectors:
      - all
    
  - name: Real-time Evidence Collection
    frequency: continuous
    event_driven: true
    controls:
      - CC7.3  # Security incidents
      - CC7.4  # Incident response
    triggers:
      - security_alert
      - incident_created
      - critical_change
    collectors:
      - datadog
      - jira
      - aws

evidence_types:
  configuration:
    sources:
      - aws_config
      - azure_policy
      - github_settings
    validation:
      - schema_validation
      - compliance_check
    
  logs:
    sources:
      - cloudtrail
      - azure_activity_log
      - application_logs
    validation:
      - timestamp_verification
      - integrity_check
    processing:
      - anonymization
      - aggregation
    
  reports:
    sources:
      - automated_reports
      - manual_attestations
    validation:
      - completeness_check
      - approval_verification
    
  screenshots:
    sources:
      - ui_automation
      - manual_capture
    validation:
      - timestamp_overlay
      - hash_verification

retention_policies:
  default:
    duration: 365  # days
    archival: true
    
  security_incidents:
    duration: 1095  # 3 years
    archival: true
    immutable: true
    
  access_logs:
    duration: 365
    archival: true
    compression: true
    
  configuration_snapshots:
    duration: 180
    archival: false
    versioning: true
```

### Evidence Validation
```python
class EvidenceValidator:
    def __init__(self):
        self.validation_rules = self._load_validation_rules()
    
    def validate(self, evidence: Evidence) -> bool:
        """Validate evidence meets SOC2 requirements"""
        # Basic validation
        if not self._validate_required_fields(evidence):
            return False
        
        # Type-specific validation
        if not self._validate_by_type(evidence):
            return False
        
        # Control-specific validation
        if not self._validate_by_control(evidence):
            return False
        
        # Data integrity validation
        if not self._validate_integrity(evidence):
            return False
        
        return True
    
    def _validate_required_fields(self, evidence: Evidence) -> bool:
        """Validate all required fields are present"""
        required_fields = [
            'evidence_id', 'control_id', 'evidence_type',
            'title', 'collection_date', 'source_system',
            'data', 'hash'
        ]
        
        for field in required_fields:
            if not hasattr(evidence, field) or getattr(evidence, field) is None:
                self._log_validation_error(
                    f"Missing required field: {field}",
                    evidence.evidence_id
                )
                return False
        
        return True
    
    def _validate_by_type(self, evidence: Evidence) -> bool:
        """Validate evidence based on type"""
        if evidence.evidence_type == EvidenceType.CONFIGURATION:
            return self._validate_configuration(evidence)
        elif evidence.evidence_type == EvidenceType.LOG:
            return self._validate_log(evidence)
        elif evidence.evidence_type == EvidenceType.REPORT:
            return self._validate_report(evidence)
        elif evidence.evidence_type == EvidenceType.SCREENSHOT:
            return self._validate_screenshot(evidence)
        
        return True
    
    def _validate_configuration(self, evidence: Evidence) -> bool:
        """Validate configuration evidence"""
        # Must have timestamp
        if 'timestamp' not in evidence.data and 'collected_at' not in evidence.data:
            return False
        
        # Must have configuration values
        if not evidence.data:
            return False
        
        return True
    
    def _validate_log(self, evidence: Evidence) -> bool:
        """Validate log evidence"""
        # Must have log entries
        if 'entries' not in evidence.data and 'logs' not in evidence.data:
            return False
        
        # Must cover the specified period
        if evidence.period_end < evidence.period_start:
            return False
        
        return True
    
    def _validate_by_control(self, evidence: Evidence) -> bool:
        """Validate evidence meets control-specific requirements"""
        control_requirements = {
            'CC6.1': self._validate_access_control_evidence,
            'CC7.1': self._validate_monitoring_evidence,
            'CC8.1': self._validate_change_management_evidence
        }
        
        if evidence.control_id in control_requirements:
            return control_requirements[evidence.control_id](evidence)
        
        return True
    
    def _validate_access_control_evidence(self, evidence: Evidence) -> bool:
        """Validate access control evidence"""
        if evidence.evidence_type == EvidenceType.REPORT:
            # Must include user list with MFA status
            if 'users' not in evidence.data:
                return False
            
            # Each user must have MFA status
            for user in evidence.data.get('users', []):
                if 'MFAEnabled' not in user:
                    return False
        
        return True
```

## Evidence Collection Dashboard
```javascript
// Real-time evidence collection monitoring
class EvidenceCollectionDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.initDashboard();
    }
    
    async initDashboard() {
        // Initialize WebSocket for real-time updates
        this.connectWebSocket();
        
        // Load initial data
        await this.loadDashboardData();
        
        // Initialize charts
        this.initCollectionStatusChart();
        this.initControlCoverageChart();
        this.initTimelineChart();
        this.initSourceSystemsChart();
        
        // Set up refresh intervals
        setInterval(() => this.refreshDashboard(), 60000); // Every minute
    }
    
    connectWebSocket() {
        this.ws = new WebSocket('wss://evidence-api/realtime');
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleRealtimeUpdate(data);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            setTimeout(() => this.connectWebSocket(), 5000);
        };
    }
    
    async loadDashboardData() {
        const response = await fetch('/api/evidence/dashboard');
        this.dashboardData = await response.json();
        
        this.updateSummaryCards();
    }
    
    updateSummaryCards() {
        // Collection statistics
        document.getElementById('totalEvidence').textContent = 
            this.dashboardData.summary.total_evidence.toLocaleString();
        
        document.getElementById('todayCollected').textContent = 
            this.dashboardData.summary.collected_today.toLocaleString();
        
        document.getElementById('controlsCovered').textContent = 
            `${this.dashboardData.summary.controls_covered} / ${this.dashboardData.summary.total_controls}`;
        
        document.getElementById('coveragePercentage').textContent = 
            `${Math.round(this.dashboardData.summary.coverage_percentage)}%`;
        
        // Update collection status
        const statusElement = document.getElementById('collectionStatus');
        if (this.dashboardData.collection_status.active_collections > 0) {
            statusElement.innerHTML = `
                <span class="badge badge-success">Active</span>
                <small>${this.dashboardData.collection_status.active_collections} collectors running</small>
            `;
        } else {
            statusElement.innerHTML = '<span class="badge badge-secondary">Idle</span>';
        }
    }
    
    initControlCoverageChart() {
        const ctx = document.getElementById('controlCoverageChart').getContext('2d');
        
        this.charts.controlCoverage = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(this.dashboardData.control_coverage),
                datasets: [{
                    label: 'Evidence Items',
                    data: Object.values(this.dashboardData.control_coverage),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Evidence Coverage by Control'
                    }
                }
            }
        });
    }
    
    initTimelineChart() {
        const ctx = document.getElementById('collectionTimelineChart').getContext('2d');
        
        // Prepare timeline data
        const last7Days = this.getLast7Days();
        const timelineData = this.processTimelineData(
            this.dashboardData.collection_timeline,
            last7Days
        );
        
        this.charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: last7Days,
                datasets: [{
                    label: 'Evidence Collected',
                    data: timelineData,
                    fill: false,
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Evidence Collection Timeline'
                    }
                }
            }
        });
    }
    
    handleRealtimeUpdate(data) {
        switch (data.type) {
            case 'evidence_collected':
                this.handleNewEvidence(data);
                break;
            case 'collection_started':
                this.handleCollectionStarted(data);
                break;
            case 'collection_completed':
                this.handleCollectionCompleted(data);
                break;
            case 'collection_failed':
                this.handleCollectionFailed(data);
                break;
        }
    }
    
    handleNewEvidence(data) {
        // Update counters
        this.dashboardData.summary.total_evidence++;
        this.dashboardData.summary.collected_today++;
        
        // Update control coverage
        if (this.dashboardData.control_coverage[data.control_id]) {
            this.dashboardData.control_coverage[data.control_id]++;
        } else {
            this.dashboardData.control_coverage[data.control_id] = 1;
        }
        
        // Refresh UI
        this.updateSummaryCards();
        this.updateCharts();
        
        // Show notification
        this.showNotification(
            `New evidence collected for ${data.control_id}`,
            'success'
        );
    }
    
    showNotification(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-header">
                <strong class="mr-auto">Evidence Collection</strong>
                <small>${new Date().toLocaleTimeString()}</small>
            </div>
            <div class="toast-body">${message}</div>
        `;
        
        document.getElementById('toastContainer').appendChild(toast);
        
        // Auto-hide after 5 seconds
        setTimeout(() => toast.remove(), 5000);
    }
}
```

## Best Practices

### Collection Strategy
1. **Automate everything possible** - Manual collection is error-prone
2. **Collect continuously** - Not just before audit
3. **Validate immediately** - Catch issues early
4. **Version control** - Track evidence changes
5. **Maintain chain of custody** - Document who/what/when
6. **Test collection scripts** - Ensure reliability
7. **Monitor collection health** - Alert on failures

### Evidence Quality
- Complete and accurate data
- Proper time periods covered
- Clear descriptions and context
- Consistent formatting
- Proper authentication/authorization
- Encrypted sensitive data
- Integrity verification

### Storage and Retention
- Centralized repository
- Hierarchical organization
- Automated retention policies
- Regular backups
- Access controls
- Audit trails
- Compliance with regulations

## Common Issues and Solutions

### Collection Failures
```python
class CollectionFailureHandler:
    def __init__(self):
        self.retry_policy = {
            'max_attempts': 3,
            'backoff_multiplier': 2,
            'initial_delay': 60  # seconds
        }
    
    async def handle_collection_failure(self, 
                                      collector: str,
                                      control_id: str,
                                      error: Exception):
        """Handle evidence collection failures"""
        # Log failure
        self.log_failure(collector, control_id, error)
        
        # Determine if retryable
        if self.is_retryable(error):
            await self.schedule_retry(collector, control_id)
        else:
            await self.escalate_failure(collector, control_id, error)
        
        # Send alert
        await self.send_failure_alert(collector, control_id, error)
    
    def is_retryable(self, error: Exception) -> bool:
        """Determine if error is retryable"""
        retryable_errors = [
            'ConnectionError',
            'TimeoutError',
            'RateLimitError',
            'TemporaryFailure'
        ]
        
        return any(err in str(type(error)) for err in retryable_errors)
```

### Evidence Gaps
```python
class EvidenceGapAnalyzer:
    def analyze_gaps(self, control_requirements: Dict, 
                    collected_evidence: List[Evidence]) -> Dict:
        """Analyze gaps in evidence collection"""
        gaps = {
            'missing_controls': [],
            'incomplete_periods': [],
            'missing_evidence_types': [],
            'recommendations': []
        }
        
        # Check control coverage
        collected_controls = set(e.control_id for e in collected_evidence)
        required_controls = set(control_requirements.keys())
        
        gaps['missing_controls'] = list(required_controls - collected_controls)
        
        # Check time period coverage
        for control_id, requirements in control_requirements.items():
            control_evidence = [e for e in collected_evidence 
                              if e.control_id == control_id]
            
            if control_evidence:
                period_gaps = self.find_period_gaps(
                    control_evidence,
                    requirements['required_period']
                )
                if period_gaps:
                    gaps['incomplete_periods'].append({
                        'control_id': control_id,
                        'gaps': period_gaps
                    })
        
        # Generate recommendations
        gaps['recommendations'] = self.generate_recommendations(gaps)
        
        return gaps
```

## Useful Resources
- Evidence collection automation guides
- SOC2 evidence requirements
- Cloud provider audit tools
- Log management best practices
- Data retention regulations