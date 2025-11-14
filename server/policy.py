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

def load_MAC_helper(mac_labels_path):
    with open(mac_labels_path) as json_file:
        json_opened = json.load(json_file)
        return json_opened
def MAC_path_helper(file_path,MAC_file_policy):
    splitted_paths = []
    for path in MAC_file_policy.keys():
        splitted_paths.append(path.split("/"))
    splitted_file_path = file_path.split("/")
    match_list = []
    for path in splitted_paths:
        match_list.append(len(set(splitted_file_path)&set(path)))
    act_file_path = splitted_paths[match_list.index(max(match_list))]
    act_string = "/"
    return act_string.join(act_file_path)
"""
MAC AT THE MOMENT ALLOWS PEOPLE TO ACCESS FILES IF NOT OTHERWISE SPECIFIED
IF MAC DEFAULT LABEL AND CLEARANCE CHANGES UPDATE THIS!!!!
"""
def MAC(user, file_path):
    
    MAC_policy = load_MAC_helper("server/data/mac_labels.json")
    MAC_user_policy = MAC_policy["user_clearances"]
    MAC_file_policy = MAC_policy["path_labels"]
    file_path = MAC_path_helper(file_path,MAC_file_policy)
    print(file_path)
    MAC_clearance_policy = MAC_policy["security_levels"]
    user_clearance = MAC_clearance_policy.get(MAC_user_policy.get(user,None),None)
    file_clearance = MAC_clearance_policy.get(MAC_file_policy.get(file_path,None),0)
    if user_clearance is None:
        return False
    if user_clearance >= file_clearance:
        return True
    return False
