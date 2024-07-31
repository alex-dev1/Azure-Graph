# Defender for cloud

### EC2 instances per account + Total Resources that defender for cloud would calculate for the CSPM ( S3 + EC2 + RDSDB )


 ```kql
 securityresources
    | where type == "microsoft.security/assessments"
    | where name in (pack_array('fead4128-7325-4b82-beda-3fd42de36920','0b168d89-4e52-45c9-bd6a-24f904abcc2e','bfa7d2aa-f362-11eb-9a03-0242ac130003'))
    | extend resourceDetails = properties['resourceDetails']
    | extend resourceSource = tolower(tostring(resourceDetails['Source']))
    | where resourceSource == "aws"
    | extend resourceType = tolower(tostring(resourceDetails['ResourceType']))
    | extend resourceId = tolower(tostring(resourceDetails['ResourceId']))
    | extend securityConnectorId = tolower(tostring(split(resourceId,"/securityentitydata/")[0]))
    | where isnotempty(securityConnectorId)
    | distinct resourceId, resourceType, securityConnectorId
    | extend computeCount = iff(resourceType == "microsoft.security/securityconnectors/ec2instance", 1 , 0)
    | extend storageCount = iff(resourceType == "microsoft.security/securityconnectors/s3bucket", 1 , 0)
    | extend dbCount = iff(resourceType == "microsoft.security/securityconnectors/rdsdb", 1 , 0)
    | extend serversCount = computeCount
    | extend dcspmCount = computeCount + storageCount + dbCount
    | summarize TotalServersInSecurityConnector = sum(serversCount), TotalDcspmInSecurityConnector = sum(dcspmCount) by securityConnectorId
    | where TotalServersInSecurityConnector > 0 or TotalDcspmInSecurityConnector > 0
    | order by TotalServersInSecurityConnector desc
```




### Display the total amount of RDSDB, EC2 and S3
```kql
    securityresources
    | where type == "microsoft.security/assessments"
    | where name in (pack_array('fead4128-7325-4b82-beda-3fd42de36920','0b168d89-4e52-45c9-bd6a-24f904abcc2e','bfa7d2aa-f362-11eb-9a03-0242ac130003'))
    | extend resourceDetails = properties['resourceDetails']
    | extend resourceSource = tolower(tostring(resourceDetails['Source']))
    | where resourceSource == "aws"
    | extend resourceType = tolower(tostring(resourceDetails['ResourceType']))
    | extend resourceId = tolower(tostring(resourceDetails['ResourceId']))
    | extend securityConnectorId = tolower(tostring(split(resourceId,"/securityentitydata/")[0]))
    | where isnotempty(securityConnectorId)
    | summarize Count=count() by resourceType
    | order by ['Count'] desc 
