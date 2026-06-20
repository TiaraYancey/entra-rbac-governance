import os
import json
import logging
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.user import User
from msgraph.generated.models.password_profile import PasswordProfile
from msgraph.generated.groups.item.members.ref.ref_request_builder import RefRequestBuilder
from msgraph.generated.models.reference_create import ReferenceCreate

# 1. Initialize Compliance Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("identity_audit.log"),
        logging.StreamHandler()
    ]
)

load_dotenv()

# 2. Extract Security Vault Values
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
ENGINEERING_GROUP_ID = os.getenv("ENGINEERING_GROUP_ID")
HR_GROUP_ID = os.getenv("HR_GROUP_ID")

# 3. Establish Live Handshake
credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)
graph_client = GraphServiceClient(credential)

async def check_user_exists(employee_id):
    """Queries Entra ID to check for pre-existing matching employee IDs."""
    query_filter = f"employeeId eq '{employee_id}'"
    result = await graph_client.users.get(query_parameters=dict(filter=query_filter))
    return len(result.value) > 0 if result and result.value else False

async def assign_to_rbac_group(user_id, user_name, department):
    """Evaluates department attribute and dynamically injects identity into the correct group."""
    group_id = None
    if department == "Engineering":
        group_id = ENGINEERING_GROUP_ID
    elif department == "HR":
        group_id = HR_GROUP_ID
        
    if not group_id:
        logging.warning(f"[RBAC_SKIP] No target group mapped for department: '{department}' for user {user_name}.")
        return

    try:
        # Build the Graph reference object payload pointing to the target User Object ID
        request_body = ReferenceCreate(
            odata_id=f"https://graph.microsoft.com/v1.0/users/{user_id}"
        )
        # Execute POST to the group's members reference endpoint
        await graph_client.groups.by_group_id(group_id).members.ref.post(request_body)
        logging.info(f"[AUDIT] [RBAC_ASSIGN] Added {user_name} to '{department}-All' security group.")
    except Exception as e:
        logging.error(f"[RBAC_ERROR] Failed to add {user_name} to group: {e}")

async def process_lifecycle():
    logging.info("[SYSTEM] Initializing automated RBAC & Identity Governance pipeline...")
    
    with open("employees.json", "r") as file:
        employees = json.load(file)
        
    for emp in employees:
        upn = f"{emp['first_name'].lower()}.{emp['last_name'].lower()}@woogwaysoutlook.onmicrosoft.com" # Replace with your actual verified domain!
        full_name = f"{emp['first_name']} {emp['last_name']}"
        
        # Identity Logic Gate: Handle active onboarding
        if emp["status"] == "Active":
            exists = await check_user_exists(emp["employee_id"])
            if exists:
                logging.info(f"[SKIPPED] User account for {full_name} already exists in the directory baseline.")
                continue
                
            logging.info(f"[PROVISION] Creating new identity pipeline object for: {full_name} ({emp['department']})")
            
            # Formulate Graph Object Structure
            new_user = User(
                account_enabled=True,
                display_name=full_name,
                mail_nickname=emp['first_name'].lower(),
                user_principal_name=upn,
                employee_id=emp['employee_id'],
                department=emp['department'],
                job_title=emp['job_title'],
                password_profile=PasswordProfile(
                    force_change_password_next_sign_in=True,
                    password="TemporarySecretPassword123!"
                )
            )
            
            try:
                # Push object into the cloud
                created_user = await graph_client.users.post(new_user)
                logging.info(f"[AUDIT] [USER_CREATED] Successfully provisioned cloud footprint for {full_name}. ID: {created_user.id}")
                
                # Fire the RBAC engine downstream immediately following a successful creation
                await assign_to_rbac_group(created_user.id, full_name, emp['department'])
                
            except Exception as e:
                logging.error(f"[SYSTEM_FAILURE] Failed to process payload for {full_name}: {e}")
                
        # Identity Logic Gate: Handle immediate offboarding/termination
        elif emp["status"] == "Terminated":
            try:
                # Isolate target cloud identity via UPN lookup
                target_user = await graph_client.users.by_user_id(upn).get()
                
                if target_user:
                    # Construct immediate mitigation payload
                    disable_payload = User(account_enabled=False)
                    await graph_client.users.by_user_id(upn).patch(disable_payload)
                    logging.info(f"[AUDIT] [ACCESS_SEVERED] Disabled account for {full_name} to freeze active sessions.")
            except Exception as e:
                logging.warning(f"[OFFBOARD_SKIP] Target individual {full_name} does not hold an active footprint: {e}")

    logging.info("[SYSTEM] Engine run completed successfully. Compliance structures synchronized.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(process_lifecycle())