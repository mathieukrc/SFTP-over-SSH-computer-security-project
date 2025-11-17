import json
import csv
def load_RBAC_helper(user_roles_path, role_perms_path):
    opened_json = None
    opened_csv = None
    stored_csv = []
    paths = []
    RBAC_policy = {}
    with open(user_roles_path,"r") as json_file, open(role_perms_path,"r") as csv_file:
        opened_json = json.load(json_file)
        opened_csv = csv.reader(csv_file, delimiter=',')
        for row in opened_csv:
            stored_csv.append(row)
            paths.append(row[1])
        for item in opened_json.items():
            if item[0] not in RBAC_policy:
                RBAC_policy[item[0]] = {}
            for role in item[1]:
                for row in stored_csv:
                    if row[0] == role:
                        resource = row[1]
                        perms = row[2:]
                        if role not in RBAC_policy[item[0]]:
                            RBAC_policy[item[0]][role] = {}
                        RBAC_policy[item[0]][role][resource] = perms
    return RBAC_policy, paths
"""
THIS IS TERRIBLE PLEASE LET ME KNOW IF YOU FIGURE OUT A BETTER WAY
"""
def RBAC_path_helper(file_path, paths):
    """Find the longest prefix match for file_path in available paths"""
    # Normalize the file path
    file_path = file_path.strip('/')
    file_parts = file_path.split('/') if file_path else []
    
    best_match = '/'
    best_match_length = 0
    
    for path in paths:
        path = path.strip('/')
        path_parts = path.split('/') if path else []
        
        # Check if this path is a prefix of file_path
        if len(path_parts) > len(file_parts):
            continue
        
        # For root path
        if path == '' or path == '/':
            if best_match_length == 0:
                best_match = '/'
            continue
            
        is_prefix = all(
            file_parts[i] == path_parts[i]
            for i in range(len(path_parts))
        )
        
        if is_prefix and len(path_parts) > best_match_length:
            best_match = '/' + '/'.join(path_parts)
            best_match_length = len(path_parts)
    
    return best_match
"""
NEED TO IMPLEMENT ALLOWED AND DENIED PERMISSION OVERRIDES
"""
def RBAC(user, file_path, action,allow_dict=None,deny_dict=None):
    RBAC_policy, paths = load_RBAC_helper("server/data/user_roles.json","server/data/role_perms.csv")
    file_path = RBAC_path_helper(file_path,paths)
    if deny_dict is not None:
        user_deny = deny_dict.get(user,None)
        if user_deny is not None:
            file_path_deny = user_deny.get(file_path,None)
            if file_path_deny is not None and action in file_path_deny:
                return False
            
    if allow_dict is not None:
        user_allow = allow_dict.get(user,None)
        if user_allow is not None:
            file_path_allow = user_allow.get(file_path,None)
            if file_path_allow is not None and action in file_path_allow:
                return True
    user_roles = RBAC_policy.get(user,None)
    if user_roles is None:
        return False
    for role in user_roles.keys():
        role_resources = user_roles.get(role,None)
        if role_resources is not None:
            resource_perms = role_resources.get(file_path,None)
            if resource_perms is not None:
                resource_perms_dict = {
                "read" : resource_perms[0],
                "write" : resource_perms[1],
                "delete" : resource_perms[2],
                "execute": resource_perms[3]
            }
                if resource_perms_dict.get(action,"N") == "Y":
                    return True
    return False

def load_MAC_helper(mac_labels_path):
    with open(mac_labels_path) as json_file:
        json_opened = json.load(json_file)
        return json_opened
"""
THIS IS TERRIBLE PLEASE LET ME KNOW IF YOU FIGURE OUT A BETTER WAY
"""
def MAC_path_helper(file_path, MAC_file_policy):
    """Find the longest prefix match for file_path in MAC policy paths"""
    # Normalize the file path
    file_path = file_path.strip('/')
    file_parts = file_path.split('/') if file_path else []
    
    best_match = '/'
    best_match_length = 0
    
    for path in MAC_file_policy.keys():
        path = path.strip('/')
        path_parts = path.split('/') if path else []
        
        # Check if this path is a prefix of file_path
        if len(path_parts) > len(file_parts):
            continue
        
        # For root path
        if path == '' or path == '/':
            if best_match_length == 0:
                best_match = '/'
            continue
            
        is_prefix = all(
            file_parts[i] == path_parts[i]
            for i in range(len(path_parts))
        )
        
        if is_prefix and len(path_parts) > best_match_length:
            best_match = '/' + '/'.join(path_parts)
            best_match_length = len(path_parts)
    
    return best_match
"""
MAC AT THE MOMENT ALLOWS PEOPLE TO ACCESS FILES IF NOT OTHERWISE SPECIFIED
IF MAC DEFAULT LABEL AND CLEARANCE CHANGES UPDATE THIS!!!!
"""
def MAC(user, file_path):
    
    MAC_policy = load_MAC_helper("server/data/mac_labels.json")
    MAC_user_policy = MAC_policy["user_clearances"]
    MAC_file_policy = MAC_policy["path_labels"]
    file_path = MAC_path_helper(file_path,MAC_file_policy)
    MAC_clearance_policy = MAC_policy["security_levels"]
    user_clearance = MAC_clearance_policy.get(MAC_user_policy.get(user,None),None)
    file_clearance = MAC_clearance_policy.get(MAC_file_policy.get(file_path,None),0)
    if user_clearance is None:
        return False
    if user_clearance >= file_clearance:
        return True
    return False

def load_DAC_helper(dac_owners_path):
    csv_stored=[]
    with open(dac_owners_path,"r") as csv_file:
        csv_opened = csv.reader(csv_file,delimiter=",")
        for row in csv_opened:
            csv_stored.append(row)
    return csv_stored
"""
THIS IS TERRIBLE PLEASE LET ME KNOW IF YOU FIGURE OUT A BETTER WAY
"""
def DAC_path_helper(file_path, DAC_policy):
    """Find the longest prefix match for file_path in DAC policy paths"""
    # Normalize the file path
    file_path = file_path.strip('/')
    file_parts = file_path.split('/') if file_path else []
    
    best_match = '/'
    best_match_length = 0
    
    for entry in DAC_policy:
        path = entry[0].strip('/')
        path_parts = path.split('/') if path else []
        
        # Check if this path is a prefix of file_path
        if len(path_parts) > len(file_parts):
            continue
        
        # For root path
        if path == '' or path == '/':
            if best_match_length == 0:
                best_match = '/'
            continue
            
        is_prefix = all(
            file_parts[i] == path_parts[i]
            for i in range(len(path_parts))
        )
        
        if is_prefix and len(path_parts) > best_match_length:
            best_match = '/' + '/'.join(path_parts)
            best_match_length = len(path_parts)
    
    return best_match
"""
VERY UGLY SOLUTION MAYBE MAKE IT MORE NICE
"""
def DAC(user,file_path,action):
    with open("server/data/user_roles.json","r") as json_file:
        json_opened = json.load(json_file)
    user_roles = json_opened.get(user,None)
    mode_dict = {7:["r","w","x"],
                 6:["r","w"],
                 5:["r","x"],
                 4:["r"],
                 3:["w","x"],
                 2:["w"],
                 1:["x"],
                 0:[]}
    DAC_policy = load_DAC_helper("server/data/dac_owners.csv")
    file_path = DAC_path_helper(file_path,DAC_policy)
    for entry in DAC_policy:
        if entry[0] == file_path:
            owner = entry[1]
            group = entry[2]
            mode = list(str(entry[3]))
            if user == owner:
                if action in mode_dict[int(mode[0])]:
                    return True
            elif user == group:
                if action in mode_dict[int(mode[1])]:
                    return True
            elif user_roles is not None:
                for role in user_roles:
                    if role == owner:
                        if action in mode_dict[int(mode[0])]:
                            return True
                    if role == group:
                        if action in mode_dict[int(mode[1])]:
                            return True                        
            else:
                if action in mode_dict[int(mode[2])]:
                    return True
    return False

def composite_rule(user,file_path,action):
    DAC_dict = {
        "read" : "r",
        "write" : "w",
        "delete" : "w",
        "execute" : "x",
    }
    if RBAC(user,file_path,action) and MAC(user,file_path) and DAC(user,file_path,DAC_dict[action]):
        return True
    return False