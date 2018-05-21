import re
import os

ZY_RULE_FILE = "zy_rules.conf"  # File we write parsed rules into.
RULES_DIR = "rules"


def parse_rule_file(input_file_name, output_file_name):
    if not isinstance(input_file_name, str) and isinstance(output_file_name, str):
        raise TypeError('bad operand type')
    coding_type = 'UTF-8' if "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" in input_file_name else 'ansi'
    with open(input_file_name, 'r', encoding=coding_type) as f:
        rule_found = 0
        rule_var = ''
        rule_op = ''
        rule_msg = 'NO_MSG'
        rule_id = ''
        for line in f.readlines():
            # Structure in line: Variable,Operator,Message,Rule_id
            if line.startswith('#') or line.startswith('SecRule TX') or line.startswith('SecMarker'):
                continue
            elif line.startswith('SecRule') and rule_found == 0:
                print(line)
                rule_found = 1
                list_line = line.split()
                rule_var = list_line[1]
                matchobj = re.match(r'SecRule (.*) (".*") *\\', line.strip())
                if matchobj:
                    rule_op = matchobj.group(2)
            elif line.strip().startswith('\"@') and rule_found == 1:
                matchobj = re.match(r'("@ .*") \n', line.lstrip())
                if matchobj:
                    rule_op = matchobj.group(1)
            elif 'msg:' in line and rule_found == 1:
                list_line = line.split('\'')
                rule_msg = list_line[1].strip()
            elif 'id:' in line and rule_found == 1:
                rule_id = re.search('\d{6}', line.strip()).group()
            elif re.match('\n', line) and rule_found == 1:
                z = open(output_file_name, "a", encoding=coding_type)
                z.write("%s\t%s\t%s\t%s\n" % (rule_id, rule_msg, rule_var, rule_op))
                rule_found = 0
                rule_var = ''
                rule_op = ''
                rule_msg = 'NO_MSG'
                rule_id = ''


def get_conf_files():
    files = os.listdir(RULES_DIR)
    type_name = []
    file_name = []
    for f in files:
        if not f.endswith('conf'):
            continue
        list_name = f[0:-5].split('-')
        file_id = float(list_name[1])
        if file_id < 913 or file_id >= 959:
            """
            Exclude several rules:
            1. initialization
            2. exclusions for wordpress, drupal, common
            3. ip reputation since we didn't buy the ip blacklist
            4. method check 
            5. DOS protection since we don't have a standard for all customer
            6. BLOCKING-EVALUATION: The rules in this configuration file enable a rule that blocks flagged anomalous 
            traffic. 
            7. CORRELATION: The rules in this configuration file facilitate the gathering of data about successful and
             unsuccessful attacks on the server.
            """
            continue
        file_name.append(f)
        type_name.append(' '.join(list_name[2:]))
    ret = dict(zip(file_name, type_name))
    return ret


if __name__ == '__main__':
    dict_rules = get_conf_files()
    print(dict_rules)
    for file in dict_rules.keys():
        parse_rule_file('%s\\%s' % (RULES_DIR, file), ZY_RULE_FILE)


#get_conf_files()
# parse_rule_file('rules\\REQUEST-931-APPLICATION-ATTACK-RFI.conf', ZY_RULE_FILE)
