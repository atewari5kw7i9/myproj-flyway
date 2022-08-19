import glob
import json
import os
import re
import subprocess

import yaml

FLYWAY_HOME = os.getenv("FLYWAY_HOME")
SNOWSQL_ACCOUNT = os.getenv("SNOWSQL_ACCOUNT")
DATABASE_WAREHOUSE = os.getenv("DATABASE_WAREHOUSE")
AWS_S3_ACCESS_KEY_ID = os.getenv("AWS_S3_ACCESS_KEY_ID")
AWS_S3_SECRET_ACCESS_KEY = os.getenv("AWS_S3_SECRET_ACCESS_KEY")
AWS_S3_NAMESPACE = os.getenv("AWS_S3_NAMESPACE")
METADATA_SQL = FLYWAY_HOME + "/rbac/sql/role"
ENV = os.getenv("DEPLOY_ENVIRONMENT")


def echo(message):
    print(message, flush=True)


def removeFile(file):
    if os.path.exists(file):
        os.remove(file)


def snowsql(args, message):
    snowsql = subprocess.run(["snowsql", *args])

    if snowsql.returncode != 0:
        echo(message + " - return code: " + str(snowsql.returncode))
        exit(1)


def bootstrapMetadataDatabase():
    snowsql([
        "-o", "exit_on_error=true",
        "-f", METADATA_SQL + "/create_metadata_database.sql"
    ], "Failed to create metadata database for roles.")


def createRolesDictionary():
    dict_ = {}

    for file in glob.glob(FLYWAY_HOME + "/rbac/roles/*.yml"):
        # Generate a file hash to track file changes
        md5sum = subprocess.run(["md5sum " + file + " | awk '{print $1}'"], shell=True, capture_output=True)
        fileHash = md5sum.stdout.decode("ascii").rstrip()
        fileName = os.path.basename(file)

        with open(file) as stream:
            doc = yaml.safe_load(stream)
            envs = {}

            if "environments" in doc:
                for env in doc['environments']:
                    envs.update({env['name']: {"items": env['items']}})

            dict_.update({doc['name']: {"description": doc['description'], "type": doc['type'],
                                       "environments": envs, "fileName": fileName, "fileHash": fileHash}})

    return dict_


def verifyRolesDictionary(roles):
    envs = ['dev', 'qa', 'prod']

    for name, value in roles.items():
        # Must have at least 1 environment given
        if len(value['environments']) == 0:
            echo("No environments definition in file: " + value['fileName'] +
                 ". Environments must be: " + str(envs))
            return False

        # Env's must be one of:
        if not all(e in envs for e in value['environments']):
            echo("Invalid environment name given in file: " + value['fileName'] +
                 ". Environments can be: " + str(envs))
            return False

            # Env's must have at least one item, e.g. role or privilage
        for eName, eValue in value['environments'].items():
            if not eValue['items'] or len(eValue['items']) < 1:
                echo("Invalid environment defintion in file: " + value['fileName'] +
                     ". Items cannot be blank for environment: " + eName)
                return False

    return True


def filterRolesByEnvironment(roles):
    return dict(filter(lambda elem: elem[1]['environments'].get(ENV) is not None, roles.items()))


def filterSystemDefinedRoles(roles):
    return dict(filter(lambda elem: elem[1]['type'] == "system-defined", roles.items()))


def is_owner_role(privileges):
    pattern = 'CREATE.*'
    for pr in privileges:
        if re.match(pattern, pr):
            return True
    return False


def is_export_role(role):
    pattern = 'EXPORT|export'
    if re.search(pattern, role):
        return True
    else:
        return False


def createRole(name, values):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "name=" + name,
        "-D", "description=" + values['description'],
        "-D", "fileName=" + values['fileName'],
        "-D", "fileHash=" + values['fileHash'],
        "-f", METADATA_SQL + "/create_role_tmpl.sql"
    ], "Failed to create role: " + name)


def deleteRole(name):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "name=" + name,
        "-f", METADATA_SQL + "/drop_role_tmpl.sql"
    ], "Failed to drop role: " + name)


def updateRoleMetadata(role, metadata):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "fileHash=" + metadata['fileHash'],
        "-D", "name=" + role,
        "-f", METADATA_SQL + "/update_role_metadata_tmpl.sql"
    ], "Failed to update role metadata: " + role)


def fetchProvisionedRoles():
    resultFile = "/tmp/roles-provisioned.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-o", "output_file=" + resultFile,
        "-f", METADATA_SQL + "/select_from_metadata.sql"
    ], "Failed to fetch roles from metadata table")

    dict_ = {}

    with open(resultFile) as fInput:
        for row in json.load(fInput):
            dict_.update({row['NAME']: {"fileHash": row['FILEHASH']}})

    return dict_


def fetchRolesLikeAny(pattern):
    resultFile = "/tmp/roles-like-any.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "pattern=" + pattern,
        "-D", "outfile=" + resultFile,
        "-f", METADATA_SQL + "/fetch_roles_like_any_tmpl.sql"
    ], "Failed to fetch roles like any: (" + pattern + ")")

    with open(resultFile) as fInput:
        return set(row['name'] for row in json.load(fInput))


def fetchSharedDatabases():
    resultFile = "/tmp/shared-databases.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "outfile=" + resultFile,
        "-f", METADATA_SQL + "/fetch_shared_databases_tmpl.sql"
    ], "Failed to fetch shared databases.")

    with open(resultFile) as fInput:
        return set(row['database_name'] for row in json.load(fInput))


def fetchGrantsToRole(role, granted_on_pattern='%'):
    resultFile = "/tmp/roles-granted-to.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "role=" + role,
        "-D", "obj_pattern=" + granted_on_pattern,
        "-D", "outfile=" + resultFile,
        "-f", METADATA_SQL + "/fetch_grants_to_role_tmpl.sql"
    ], "Failed to fetch roles granted to role: " + role)

    with open(resultFile) as fInput:
        return json.load(fInput)


def revokeGrantOnRole(source, destination):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "source=" + source,
        "-D", "destination=" + destination,
        "-f", METADATA_SQL + "/revoke_role_from_role_tmpl.sql"
    ], "Failed to revoke role: " + source + " granted to role: " + destination)


def revokePrivilegeFromRole(privilege, role):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "privilege=" + privilege,
        "-D", "role=" + role,
        "-f", METADATA_SQL + "/revoke_privilege_from_role_tmpl.sql"
    ], "Failed to revoke privilege: " + privilege + " from role: " + role)


def grantRoleToRole(source, destination):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "source=" + source,
        "-D", "destination=" + destination,
        "-f", METADATA_SQL + "/grant_role_to_role_tmpl.sql"
    ], "Failed to grant role: " + source + " to role: " + destination)


def grantRoleToRoles(role_to_grant, roles):
    for role in roles:
        grantRoleToRole(source=role_to_grant, destination=role)


def grantUsersToRole(role, users):
    # Note here we are using the sql from the user sql
    for user in users:
        snowsql([
            "-o", "exit_on_error=true",
            "-D", "role=" + role,
            "-D", "user_id=" + user,
            "-f", METADATA_SQL + "/../user/grant_role_to_user_tmpl.sql"
        ], "Failed to grant role: " + role + " to user: " + user)


def grantPrivilegeToRole(role, privilege):
    snowsql([
        "-o", "exit_on_error=true",
        "-D", "role=" + role,
        "-D", "privilege=" + privilege,
        "-f", METADATA_SQL + "/grant_privilege_to_role_tmpl.sql"
    ], "Failed to grant privilege: " + privilege + " to role: " + role)


def updateRolePermissions(roles, pRoles):
    # Order of exeuction:
    # 1) All role type: privilege
    # 2) All role type: collection
    #
    # See /roles/README.md for details on what privilege and collection types are
    updateSystemDefinedRoles(roles, pRoles)
    updatePrivilegeRoles(roles, pRoles)
    updateCollectionRoles(roles)


def prepareGrantedPrivilegesForRevoking(provisionedPrivileges):
    # filter out OWNERSHIP and ACCOUNT level privileges.
    # OWNERSHIP privileges cannot be revoked, only granted.
    # Powerful ACCOUNT level privileges are managed by ACCOUNTADMIN
    notOwnershipPrivileges = [grant for grant in provisionedPrivileges
                              if "OWNERSHIP" not in grant['privilege']
                              and "ACCOUNT" not in grant['granted_on']]

    sharedDatabases = fetchSharedDatabases()
    privilegesToRevoke = set()
    for grant in notOwnershipPrivileges:
        # before revoking access on function, it's reference should be aligned
        if 'FUNCTION' in grant['granted_on']:
            functionWithoutParamNames = re.sub(r'\w+ ', '', grant['name'])
            functionWithoutReturnType = re.sub(r':.*', '', functionWithoutParamNames)
            functionNameAligned = functionWithoutReturnType.replace('"', '')
            privilegesToRevoke.add(grant['privilege'] + ' ON ' + grant['granted_on'] + ' ' + functionNameAligned)
        # Revoking access on role
        elif 'ROLE' in grant['granted_on']:
            privilegesToRevoke.add("ROLE " + grant['name'])
        # Revoking access on shared db can be done via revoking IMPORTED PRIVILEGES rather than revoking separate individual grant
        elif grant['name'].split('.')[0] in sharedDatabases:
            privilegesToRevoke.add("IMPORTED PRIVILEGES ON DATABASE " + grant['name'].split('.')[0])
        else:
            privilegesToRevoke.add(
                grant['privilege'] + ' ON ' + grant['granted_on'].replace('_', ' ') + ' ' + grant['name'])

    return privilegesToRevoke


def updateSystemDefinedRoles(roles, pRoles):
    for name, value in roles.items():
        if value['type'] == "system-defined":
            # No changes since last execution
            if name in pRoles and value['fileHash'] == pRoles.get(name)['fileHash']:
                echo("Grants for: " + name + " already applied.")
            else:
                echo("Grants for system-defined role: " + name + " changed.")

                provisionedGrants = fetchGrantsToRole(role=name)
                provisionedPrivileges = prepareGrantedPrivilegesForRevoking(provisionedGrants)
                privileges = set(" ".join(grant.split()) for grant in value['environments'][ENV]['items'])

                # revoke all granted privilege
                for privilege in provisionedPrivileges:
                    echo("Revoking grant: " + privilege + " from role: " + name)
                    revokePrivilegeFromRole(privilege=privilege, role=name)

                # grant all new privileges
                for privilege in privileges:
                    echo("Granting: " + privilege + " to role: " + name)
                    grantPrivilegeToRole(role=name, privilege=privilege)


def roleHasEnoughGrants(role, attributes):
    echo("Checking if role " + role + " did not lose grants on recreated objects...")
    grantsToRole = fetchGrantsToRole(role)

    objectsGranted = set(grant['name'] for grant in grantsToRole)
    objectsToGrant = set(grantStr.split(' ')[-1] for grantStr in attributes['environments'][ENV]['items'])
    objectsToGrant.discard('ACCOUNT')

    return objectsToGrant.issubset(objectsGranted)


def updatePrivilegeRoles(roles, pRoles):
    for name, value in roles.items():
        if value['type'] == "privilege":
            # No changes for regular role since last execution
            if name in pRoles and value['fileHash'] == pRoles.get(name)['fileHash'] and not is_export_role(name):
                echo("Grants for: " + name + " already applied.")
                continue

            # No changes for export role since last execution
            # (some export roles, like EXPORT_RESPONSYS may have objects re-crerated on their side.
            # So extra check for losing grants is performed for this kind of roles)
            if name in pRoles and value['fileHash'] == pRoles.get(name)['fileHash'] and is_export_role(name) and roleHasEnoughGrants(name, value):
                echo("Grants for export role : " + name + " already applied.")
                continue

            privileges = set(" ".join(grant.split()) for grant in value['environments'][ENV]['items'])
            if name in pRoles and is_owner_role(privileges):
                # revoke/regrant for OWNER roles
                # Not to drop a role and recreate it (it causes lost of priviliges on ACCOUNT level (e.g EXECUTE ON ACCOUNT)
                # and OWNERSHIP privileges, revoke and regrant privileges.
                echo("Grants for privilege role: " + name + " changed. Since this is OWNER role, grants are revoked and re-granted.")
                provisionedGrants = fetchGrantsToRole(role=name)
                provisionedPrivileges = prepareGrantedPrivilegesForRevoking(provisionedGrants)

                # revoke all granted privilege
                for privilege in provisionedPrivileges:
                    echo("Revoking grant: " + privilege + " from role: " + name)
                    revokePrivilegeFromRole(privilege=privilege, role=name)

            if name in pRoles and not is_owner_role(privileges):
                echo("Grants for privilege role: " + name + " changed. Since this is non-OWNER role, the role is dropped and re-created.")
                users = fetchUsersOfRole(name)
                roles = fetchRolesWithUsageOnRole(name)
                deleteRole(name)
                createRole(name, value)
                grantUsersToRole(name, users)
                grantRoleToRoles(name, roles) # better name

            # grant all new privileges
            for privilege in privileges:
                echo("Granting: " + privilege + " to role: " + name)
                grantPrivilegeToRole(role=name, privilege=privilege)

            updateRoleMetadata(role=name, metadata=value)


def fetchUsersOfRole(role):
    resultFile = "/tmp/users-of-role.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "role=" + role,
        "-D", "outfile=" + resultFile,
        "-f", METADATA_SQL + "/fetch_users_of_role_tmpl.sql"
    ], "Failed to fetch users of role: " + role)

    with open(resultFile) as fInput:
        return set(row['grantee_name'] for row in json.load(fInput))


def fetchRolesWithUsageOnRole(role):
    resultFile = "/tmp/roles-of-role.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "role=" + role,
        "-D", "outfile=" + resultFile,
        "-f", METADATA_SQL + "/fetch_roles_with_usage_on_role_tmpl.sql"
    ], "Failed to fetch roles with usage on role: " + role)

    with open(resultFile) as fInput:
        return set(row['grantee_name'] for row in json.load(fInput))


def updateCollectionRoles(roles):
    for name, value in roles.items():
        if value['type'] == "collection":
            # Format items into a list of comma separated strings
            patternString = None

            for items in value['environments'].get(ENV).values():
                patternString = ', '.join("'{0}'".format(item) for item in items)

            allRoles = fetchRolesLikeAny(patternString)
            assignedGrants = fetchGrantsToRole(role=name, granted_on_pattern="ROLE")
            assignedRoles = set(grant['name'] for grant in assignedGrants)

            # Roles to revoke
            for role in list(assignedRoles - allRoles):
                echo("Revoking role: " + role + " from role: " + name)
                revokeGrantOnRole(role, name)

            # Roles to grant
            for role in list(allRoles - assignedRoles):
                echo("Granting role: " + role + " to role: " + name)
                grantRoleToRole(role, name)


def main(args=None):
    echo("Preparing roles for provisioning ...")
    bootstrapMetadataDatabase()
    roles = createRolesDictionary()

    if verifyRolesDictionary(roles):
        # We only want to work with roles that apply to this enviroment
        systemRoles = filterSystemDefinedRoles(roles)
        roles = filterRolesByEnvironment(roles)
        pRoles = fetchProvisionedRoles()

        # Delete any roles that are no-longer provisioned, e.g. referenced in source.
        # Any system-defined role cannot be dropped.
        for role in list(set(pRoles.keys()) - set(roles.keys()) - set(systemRoles.keys())):
            echo("Dropping role: " + role)
            deleteRole(role)

        # Provision any new roles except any system-defined role.
        for role in list(set(roles.keys()) - set(pRoles.keys()) - set(systemRoles.keys())):
            echo("Creating role: " + role)
            doc = roles.get(role)
            createRole(role, doc)

        updateRolePermissions(roles, pRoles)

    else:
        echo("Configuration error.  Aborting!")
        exit(1)

    echo("Role provisioning completed.")


if __name__ == "__main__":
    main()
