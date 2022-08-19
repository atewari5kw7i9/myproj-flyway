import json
import os
import subprocess

import yaml

FLYWAY_HOME = os.getenv("FLYWAY_HOME")
SNOWSQL_ACCOUNT = os.getenv("SNOWSQL_ACCOUNT")
DATABASE_WAREHOUSE = os.getenv("DATABASE_WAREHOUSE")
AWS_S3_ACCESS_KEY_ID = os.getenv("AWS_S3_ACCESS_KEY_ID")
AWS_S3_SECRET_ACCESS_KEY = os.getenv("AWS_S3_SECRET_ACCESS_KEY")
AWS_S3_NAMESPACE = os.getenv("AWS_S3_NAMESPACE")
ENV = os.getenv("DEPLOY_ENVIRONMENT")

completed = []


def echo(message):
    print(message, flush=True)


def removeFile(file):
    if os.path.exists(file):
        os.remove(file)


def createMigrationsDictionary():
    dict_ = {}

    with open(FLYWAY_HOME + "/databases/migrations.yml") as stream:
        migrations = yaml.safe_load_all(stream)

        for doc in migrations:
            db = {"type": doc['type'],
                  "description": doc['description'],
                  "dependencies": [],
                  "children": []}
            if "dependencies" in doc:
                db['dependencies'] = doc['dependencies']
            if "children" in doc:
                db['children'] = doc['children']

            if doc['type'] in ('sandbox','teradatanew') and "schemas" in doc:
                schemas = []

                for schema in doc['schemas']:
                    if "sources" in schema:
                        schemas.append({schema['name']: {"description": schema['description'],
                                                         "sources": schema['sources']}})
                    else:
                        schemas.append({schema['name']: {"description": schema['description'],
                                                         "sources": []}})
                db.update({"schemas": schemas})
            dict_.update({doc['name']: db})
    return dict_


def checkForUnresolvedDependencies(migrations, name, value, issue_dict, key_name):
    for dep in value[key_name]:
        # Check for un-resolvable dependency
        if dep not in migrations.keys():
            issue_dict['UnResolved'].append(f"Un-resolvable {key_name} found for: " + name + " -> " + dep)


def checkForCircularDependencies(migrations, name, value, issue_dict, key_name):
    for dep in value[key_name]:
        # Check for circular dependencies
        try:
            if name in migrations.get(dep)[key_name]:
                issue_dict['Circular_Relationships'].append(
                    f"Circular {key_name} found between: " + name + " and " + dep)
        except TypeError as typerr:
            if typerr.args[0] == "'NoneType' object is not subscriptable":
                pass
            else:
                raise typerr


def verifyDependencies(migrations):
    database_issues = {'UnResolved': [],
                       'Circular_Relationships': [],
                       'Multiple_Associations': []}
    for name, value in migrations.items():
        checkForUnresolvedDependencies(migrations, name, value, database_issues, 'dependencies')
        checkForCircularDependencies(migrations, name, value, database_issues, 'dependencies')

        if "team" == value['type'] and value['children']:
            checkForUnresolvedDependencies(migrations, name, value, database_issues, 'children')
            checkForCircularDependencies(migrations, name, value, database_issues, 'children')
            for child in value['children']:
                # Check for child to multiple parent team database associations
                for other_db_name, other_db_value in migrations.items():
                    if name != other_db_name and other_db_value['type'] == "team":
                        if child in other_db_value['children']:
                            database_issues['Multiple_Associations'].append(
                                f"Child Team Database {child} is associated two multiple parent databases {name} and {other_db_name}.")

        # Check sandbox dependencies
        if "sandbox" == value['type'] and "schemas" in value:
            for schema in value['schemas']:
                for sName, sValue in schema.items():
                    if not all(elem in value['dependencies'] for elem in sValue['sources']):
                        echo(f"Missing source dependency found for: {sName} - sources having: {str(sValue['sources'])} "
                             f"{name} having: {str(value['dependencies'])}")
                        return False

    if [val for vals in database_issues.values() for val in vals]:
        echo("The following issues have been detected with database creation:")
        for issues in list(database_issues.values()):
            echo('\t'+'\n\t'.join(issues))
        return False

    return True


def formatDatabaseName(name):
    return name.upper()


def snowsql(args, message):
    snowsql = subprocess.run(["snowsql", *args])

    if snowsql.returncode != 0:
        echo(message + " - return code: " + str(snowsql.returncode))
        exit(1)


def is_future_ownership_granted(database):
    echo("Checking if database has already FUTURE OWNERSHIP applied...")

    resultFile = "/tmp/future_ownerships.json"
    removeFile(resultFile)
    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "outfile=" + resultFile,
        "-D", "database=" + database,
        "-f", "./databases/templates/general/fetch_future_ownerships_tmpl.sql"
    ], "Failed to fetch databases.")

    with open(resultFile) as fInput:
        is_granted = len(json.load(fInput)) > 0

    return is_granted


def is_share_granted(database):
    echo("Checking if database has already SHARE DB Created...")

    resultFile = "/tmp/shared_database.json"
    removeFile(resultFile)
    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-o", "log_level=DEBUG",
        "-D", "outfile=" + resultFile,
        "-D", "database_name=" + database,
        "-f", "./databases/templates/share/fetch_share_name_tmpl.sql"
    ], "Failed to fetch share details for given database" + database)

    dict_ = {}
    with open(resultFile) as fInput:
        share_list = json.load(fInput)
        if len(share_list) > 0:
            dict_.update(share_list[0])
        else:
            echo(f"Share for {database} not provided for the account")
        return dict_


def dropSandboxScheams(databaseName, schemas):
    # Working with a dictionary object in this context proved to be a bit difficulty as I could not figure a way
    # to simply check if a name exists.  This is because we have a list of dictionary objects that need to be
    # flattened.
    schemaNames = []

    for doc in schemas:
        for schema in doc.keys():
            schemaNames.append(schema)

    # Query for scheams belonging to the given database and write these to a file
    resultFile = "/tmp/schemas.json"
    removeFile(resultFile)

    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "database=" + databaseName,
        "-D", "outfile=" + resultFile,
        "-f", "./databases/templates/sandbox/fetch_schemas_tmpl.sql"
    ], "Failed to fetch schemas for: " + databaseName)

    with open(resultFile) as fInput:
        queryResults = json.load(fInput)

    # For any schema that is not defined in the our migtations, drop it
    for schema in queryResults:
        schemaName = schema['name'].lower()

        if schemaName not in schemaNames:
            snowsql([
                "-o", "exit_on_error=true",
                "-D", "database=" + databaseName,
                "-D", "schema=" + schemaName,
                "-f", "./databases/templates/sandbox/drop_schema_tmpl.sql"
            ], "Failed to drop schema: " + schemaName + " from database: " + databaseName)


def dropDatabases(repo_databases):
    echo("Checking databases to drop...")

    resultFile = "/tmp/databases.json"
    removeFile(resultFile)
    snowsql([
        "-o", "exit_on_error=true",
        "-o", "output_format=json",
        "-o", "friendly=false",
        "-D", "outfile=" + resultFile,
        "-D", "db_owner=" + "GDA_SERVICE",
        "-f", "./databases/templates/general/fetch_databases_tmpl.sql"
    ], "Failed to fetch databases.")

    with open(resultFile) as fInput:
        provisioned_databases = set(row['name'].lower() for row in json.load(fInput))
    # helper databases that were created with gda-database pipeline but does not relate to any type
    db_exceptions = {"provision_metadata"}

    for database in provisioned_databases - repo_databases - db_exceptions:
        echo("Dropping database " + database)

        snowsql([
            "-o", "exit_on_error=true",
            "-o", "friendly=false",
            "-D", "database=" + database,
            "-f", "./databases/templates/general/drop_database_tmpl.sql"
        ], "Failed to drop database " + database)


def bootstrapDatabase(name, value):
    sourcePath = FLYWAY_HOME + "/databases/templates/" + value['type']
    databaseName = formatDatabaseName(name)

    if "share" == value['type']:
        share_dict = is_share_granted(databaseName)
        if share_dict.get('database_name') != '':
            echo(f"Share Database {databaseName} already created for share {share_dict['name']}")
        else:
            echo(f"Creating Share Database {databaseName} from share {share_dict['name']}")
            snowsql([
                "-o", "exit_on_error=true",
                "-D", "database=" + databaseName,
                "-D", "share_name=" + share_dict['name'],
                "-D", "description=" + value['description'],
                "-f", sourcePath + "/create_database_tmpl.sql"
            ], "Bootstrap database failed for: " + databaseName)
    else:
        snowsql([
            "-o", "exit_on_error=true",
            "-D", "database=" + databaseName,
            "-D", "description=" + value['description'],
            "-f", sourcePath + "/create_database_tmpl.sql"
        ], "Bootstrap database failed for: " + databaseName)

    if "team" == value['type'] and not is_future_ownership_granted(databaseName):
        echo("Granting FUTURE OWNERSHIP in database " + databaseName)
        snowsql([
            "-o", "exit_on_error=true",
            "-D", "database=" + databaseName,
            "-f", sourcePath + "/grant_future_ownership_tmpl.sql"
        ], "Granting future OWNERSHIP failed for: " + databaseName)

    if "secure" == value['type'] and not is_future_ownership_granted(databaseName):
        echo("Granting FUTURE OWNERSHIP in database " + databaseName)
        snowsql([
            "-o", "exit_on_error=true",
            "-D", "database=" + databaseName,
            "-f", sourcePath + "/grant_future_ownership_tmpl.sql"
        ], "Granting future OWNERSHIP failed for: " + databaseName)

    if value['type'] in ('sandbox','teradatanew'):
        # Clean up any un-provisioned scheams
        schemas = value['schemas']
        sandbox_flag = 0
        if value['type'] == 'sandbox':
            sandbox_flag = 1
            dropSandboxScheams(name, schemas)

        for doc in schemas:
            for schema, value in doc.items():
                # Create the database and schema
                if schema == "PRD_DWH_HR_VIEW":
                    snowsql([
                        "-o", "exit_on_error=true",
                        "-D", "database=" + databaseName,
                        "-D", "description=" + value['description'],
                        "-D", "schema=" + schema,
                        "-f", sourcePath + "/create_secure_schema_tmpl.sql"
                    ], "Create schema failed for: " + schema)
                else:
                    snowsql([
                        "-o", "exit_on_error=true",
                        "-D", "database=" + databaseName,
                        "-D", "description=" + value['description'],
                        "-D", "schema=" + schema,
                        "-f", sourcePath + "/create_schema_tmpl.sql"
                    ], "Create schema failed for: " + schema)

                    # Grant schema access to sources
                    if sandbox_flag == 1:
                        for source in value['sources']:
                            snowsql([
                                "-o", "exit_on_error=true",
                                "-D", "schema=" + schema,
                                "-D", "source=" + source,
                                "-f", sourcePath + "/grant_source_to_schema_tmpl.sql"
                            ], "Failed to grant: " + schema + " access to source: " + source)

def migrateDatabase(name):
    sqlLocation = FLYWAY_HOME + "/databases/sql/" + name
    databaseName = formatDatabaseName(name)

    flyway = subprocess.run([
        FLYWAY_HOME + "/flyway",
        "-url=jdbc:snowflake://" + SNOWSQL_ACCOUNT + ".snowflakecomputing.com/?db=" + databaseName + "&warehouse=" + DATABASE_WAREHOUSE,
        "-locations=filesystem:" + sqlLocation,
        "-placeholders.database.name=" + databaseName,
        "-placeholders.aws.s3.access.key.id=" + AWS_S3_ACCESS_KEY_ID,
        "-placeholders.aws.s3.secret.access.key=" + AWS_S3_SECRET_ACCESS_KEY,
        "-placeholders.aws.s3.namespace=" + AWS_S3_NAMESPACE,
        "migrate"
    ])

    if flyway.returncode != 0:
        echo("Migrate database failed for: " + databaseName + " - return code: " + str(flyway.returncode))
        exit(1)


def executeReadyWork(migrations):
    for name, value in migrations.items():
        # Grab the list of dependencies and see if they are all satisified, e.g. none or contained in the completed list
        if all(elem in completed for elem in value['dependencies']):
            echo("Processing database migrations for: " + name)

            bootstrapDatabase(name, value)
            if value['type'] not in ["team", "share", "teradata"]:
                migrateDatabase(name)
            completed.append(name)

        else:
            echo("Waiting for dependencies to be completed: " + name)


def removeCompletedWork(migrations):
    for name in completed:
        migrations.pop(name, None)


def main(*args):
    echo("Preparing database migrations for processing ...")
    migrations = createMigrationsDictionary()
    repo_databases = {db for db in migrations.keys()}

    if verifyDependencies(migrations):
        while True:
            executeReadyWork(migrations)
            removeCompletedWork(migrations)

            if not bool(migrations):
                break
        if ENV != 'dev':
            dropDatabases(repo_databases)
    else:
        echo("Configuration error.  Aborting!")
        exit(1)

    echo("Completed processing database migraitons.")


if __name__ == "__main__":
    main()
