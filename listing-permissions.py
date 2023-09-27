# this script is to list permissions and revoke permissions in lake formation using boto3

import boto3
import botocore

# boto3.setup_default_session(profile_name='aws-dev')
# this is used to set up credentials

aws_account='xxxxxxxxxx'


lf = boto3.client('lakeformation')

print("------------- Listing the permissions -------------")

args = {}
next_token = ""
token = ""
count = 0
revoke_count = 0
whitelist = [aws_account, 'arn:aws:iam::Account-ID:role/roleName']
# if you want to whitelist any principal, you add the principal in here.

while token == "" or token != next_token:
    token = next_token
    if token != "":
        args['NextToken']=token
    response = lf.list_permissions(**args)
    if "NextToken" in response.keys():
        next_token = response['NextToken']
    permissions = response['PrincipalResourcePermissions']
    for permission in permissions:
        count = count+1
        principal_identifier = permission['Principal']
        resource = permission['Resource']
        permit = permission['Permissions']

        print('-----this is the principal -------')
        print(principal_identifier)

        print('-----this is attached resource -------')
        print(resource)

        print('-----these are permissions -------')
        print(permit)
     
        if "Table" in resource.keys():
            if "Name" in resource['Table'].keys() and "TableWildcard" in resource['Table'].keys():
                del resource['Table']['Name']
    


        if principal_identifier['DataLakePrincipalIdentifier'] not in whitelist and ("LFTag" not in resource.keys() and "LFTagPolicy" not in resource.keys()):
            print("------we are going to revoke!!!!!!!!--------")
            try:
                lf.revoke_permissions(
                    Principal=principal_identifier,
                    Resource=resource,
                    Permissions=permit
                )
                revoke_count = revoke_count + 1
            except botocore.exceptions.ClientError as err:
                if err.response["Error"]["Code"] == 'AccessDeniedException':
                    if "TableWithColumns" in resource.keys():
                        table_withcolumns = resource['TableWithColumns']
                        table_withcolumns.pop("Name", None)
                        table_withcolumns.pop("ColumnNames", None)
                        table_withcolumns.pop("ColumnWildcard", None)
                        table_withcolumns["TableWildcard"] = {}
                        del resource["TableWithColumns"]
                        resource["Table"] = table_withcolumns
                    lf.revoke_permissions(
                        Principal=principal_identifier,
                        Resource=resource,
                        Permissions=permit
                    )
                    revoke_count = revoke_count + 1
                else:
                    raise err
        else:
            print("permissions are not revoked")

    
print("total permissions are:", count)
print("total permissions revoked is:", revoke_count)
print("permissions that not revoked are:", count-revoke_count)
