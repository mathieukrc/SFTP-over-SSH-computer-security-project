import json
import csv
def load_RBAC_helper(user_roles_path, role_perms_path):
    opened_json = None
    opened_csv = None
    stored_csv = []
    RBAC_policy = {}
    with open(user_roles_path,"r") as json_file, open(role_perms_path,"r") as csv_file:
        opened_json = json.load(json_file)
        opened_csv = csv.reader(csv_file, delimiter=',')
        for row in opened_csv:
            stored_csv.append(row)
        for item in opened_json.items():
            for role in item[1]:
                if item[0] in RBAC_policy:
                    for row in stored_csv:
                        if row[0] == role:
                            resource = row[1]
                            perms = row[2:]
                            RBAC_policy[item[0]][role] = {resource:perms}
                else:
                    for row in stored_csv:
                        if row[0] == role:
                            resource = row[1]
                            perms = row[2:]
                            RBAC_policy[item[0]] = {role:{resource:perms}}
    return RBAC_policy
def RBAC(user, resource, action):
    RBAC_policy = load_RBAC_helper("server/data/user_roles.json","server/data/role_perms.csv")
    user_roles = RBAC_policy.get(user,None)
    if user_roles is None:
        return False
    for role in user_roles.keys():
        role_resources = user_roles.get(role,None)
        if role_resources is not None:
            resource_perms = role_resources.get(resource,None)
            if resource_perms is not None:
                if action in resource_perms:
                    return True
    return False
