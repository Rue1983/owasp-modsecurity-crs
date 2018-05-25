from collections import namedtuple
from collections import defaultdict
from collections import OrderedDict
import os
import sqlite3
import re
import regex
regex.DEFAULT_VERSION = regex.V1
global DATA_FILES

ZY_RULE_FILE = "zy_rules.conf"  # File we write parsed rules into.
RULES_DIR = "rules"
DROP_LIST = set(['REQBODY_ERROR', 'MULTIPART_STRICT_ERROR', 'IP:REPUT_BLOCK_FLAG', 'XML:/*', 'RESPONSE_BODY', 'FILES'])
WAITING_LIST = set(['FILES_NAMES', 'REQUEST_BODY', 'TX:MAX_NUM_ARGS', 'TX:ARG_NAME_LENGTH', 'TX:ARG_LENGTH',
                'TX:TOTAL_ARG_LENGTH', 'TX:MAX_FILE_SIZE', 'COMBINED_FILE_SIZES'])
COOKIE = 'Cookie'
db_name = 'alertsbig.db'


def get_all_variable_types(file_name):
    ret = []
    op = []
    if not isinstance(file_name, str):
        raise TypeError('bad operand type')
    with open(file_name, 'r', encoding='ansi') as f:
        for line in f.readlines():
            list_line = line.split('\t')
            a = list_line[2].split('|')
            op.append(list_line[3][:10])
            for i in a:
                ret.append(i)
    new_ret = list(set(ret))
    new_ret.sort(key=ret.index)
    print('%s\n%s' % (new_ret, op))


def get_all_operator_types(file_name):
    ret = []
    op = []
    if not isinstance(file_name, str):
        raise TypeError('bad operand type')
    with open(file_name, 'r', encoding='ansi') as f:
        for line in f.readlines():
            list_line = line.split('\t')
            ret.append(list_line[3])
    for i in ret:
        ii = i.strip('"')
        matchobj = re.match(r'^!*@*(\w+) .*', ii)
        if matchobj:
            op.append(matchobj.group(1))
        matchobj = re.match(r'^!*@*(\w+)', ii)
        print(matchobj)
        if matchobj:
            op.append(matchobj.group(1))
    new_ret = list(set(op))
    new_ret.sort(key=op.index)
    for i in new_ret:
        print(i)
    return new_ret


def get_all_rules(filename):
    """
    Get all rules from given file which is saved rules we collect from modSecurity
    :param filename:
    :return: all rules and all files' data in 2 dicts
    """
    dict_rules = OrderedDict()
    dict_datafiles = {}
    dt = []
    Rules = namedtuple('Rule', ['message', 'variables', 'oprators'])
    with open(filename, 'r', encoding='UTF-8') as f:
        for line in f.readlines():
            if line.startswith('#'):
                # Ignore comments
                continue
            li = line.split('\t')
            dict_rules[li[0]] = Rules._make(li[1:])
            if li[3].strip('"\n\r').lower().startswith('@pmf'):
                data_file_name = li[3].strip('"\n\r').split(' ')[1]
                dt.append(data_file_name)
    for file in dt:
        f_path = '%s\\%s' % (RULES_DIR, file)
        f_list = []
        with open(f_path, 'r', encoding='UTF-8') as f:
            for line in f.readlines():
                if line and not line.startswith('#'):
                    f_list.append(line.rstrip('\n'))
        if f_list:
            dict_datafiles[file] = set(f_list)
    #print(dict_datafiles)
    return dict_rules, dict_datafiles
#get_all_rules(ZY_RULE_FILE)


def get_vars_from_request(request):
    args_get = {}
    args_get_names = []
    request_filename = ''
    request_basename = ''
    query_string = ''
    method = ''
    uri = ''
    request_protocol = ''
    match_vars = re.match(r'(\w+) (.*) (HTTP/\d?.?\d?)$', request)
    method = match_vars.group(1)
    uri = match_vars.group(2)
    request_protocol = match_vars.group(3)

    sector = uri.split('?')
    request_filename = sector[0]
    request_basename = request_filename.split('/')[-1]
    if len(sector) > 1:
        loc = uri.find('?')
        query_string = uri[loc+1:]
    if '=' in uri:
        tmp = []
        for s in sector:
            tmp = tmp + s.split('&')
        for t in tmp:
            arg = t.split('=')
            if len(arg) > 1:
                arg[0] = arg[0].split('/')[-1]
                args_get[arg[0]] = arg[1]
                args_get_names.append(arg[0])
    print('args_get:%s\nargs_get_names:%s\n request_filename:%s\n request_basename:%s\n '
          'query_string:%s\n method:%s\n uri:%s\n request_protocol:%s\n'
          % (args_get, args_get_names, request_filename, request_basename, query_string, method, uri, request_protocol))
    ret = []
    ret.append(method)
    ret.append(args_get)
    ret.append(args_get_names)
    ret.append(request_filename)
    ret.append(request_basename)
    ret.append(query_string)
    ret.append(request_protocol)
    return ret    #args_get, args_get_names, request_filename, request_basename, query_string, method, uri, request_protocol
# request = 'GET /bemarket/shop/index.php?pageurl=viewpage&filename=../../../../../../../../../../../../../../etc/passwd HTTP/1.1'
# request2 = 'GET /htgrep/file=index.html&hdr=/etc/passwd HTTP/2'
# request3 = 'GET /scripts/script/cat_for_gen.php?ad=1&ad_direct=../&m_for_racine=%3C/option%3E%3C/SELECT%3E%3C?phpinfo();?%3E HTTP/1.1'
# request4 = 'GET /scripts/script/cat_for_gen.php?ad=1&ad_direct=../&m_for_racine=</option></SELECT><?phpinfo();?> HTTP/0.9'
# request5 = 'GET /portal/js/)&&m.contains(h,d)&&(d.src?m._evalUrl&&m._evalUrl(d.src):m.globalEval((d.text||d.textContent||d.innerHTML|| HTTP/2'
# request6 = 'GET /browserconfig.xml HTTP/1.1'
# get_vars_from_request(request3)


def execute_rule(alert, header, rule):
    """
    Make a list of rule result for each variable, and return list lenth, if it's true which means record match the rule.
    :param alert:
    :param header:
    :param rule:
    :return:
    """
    ret = []
    variables = parse_variables(alert, header, rule.variables)
    operators = rule.oprators
    operators = operators.strip('"\n\r')
    if operators.endswith('"'):
        operators = operators[:-1]
    is_op_neg = 0
    if operators.startswith('!@'):
        is_op_neg = 1
        operators = operators.strip('!')
    print('test111 variables', variables)
    print('test222 operators', operators)
    # print(alert, '\n', header, '\n')
    if not variables:
        return ret
    for v in variables:
        if operators.startswith('@rx '):
            operators = operators[4:]
            matchobj = regex.search(r'%s' % operators, str(v))
            if matchobj or is_op_neg:
                ret.append(1)
                #print('operator: %s\nv: %s\nmatchobj: %s' % (operators, v, matchobj))
                #print('matched for @rx is :', matchobj.group(0))
            else:
                continue
        elif not operators.startswith('@'):
            if operators != '^$' and not v and not is_op_neg:
                continue

            matchobj = regex.search(r'%s' % operators, str(v))
            print(operators, str(v), matchobj)
            if matchobj or is_op_neg:
                ret.append(1)
                #print('operator: %s\nv: %s\nmatchobj: %s' % (operators, v, matchobj))
                #print('matched for no is :', matchobj.group(0))
            else:
                continue
        elif operators.lower().startswith('@pmf'):  # @pmf equal to @pmFromFiles
            if not v:
                continue
            file_name = operators.split(' ')[1]
            for op in DATA_FILES[file_name]:
                if op in v:
                    ret.append(1)
                    print('#################', op, v, file_name)
                    continue
            #ret.append('captured pmFromFile') # handle the !
        elif operators.lower().startswith('@pm'):  # @pmf equal to @pmFromFiles
            if not v:
                continue
            op_list = operators.split(' ')[1:]
            for op in op_list:
                if op in str(v):
                    ret.append(1)
                    continue
        elif operators.startswith('@eq'):
            print('captured eq', operators, v)
            if not v:
                continue
            if (int(operators[4:]) == int(v)) or is_op_neg:
                ret.append('1')
              # handle the !
        elif operators.startswith('@validateByteRange'):
            pass
            #ret.append('captured validateByteRange')  # handle the !
        elif operators.startswith('@within'):
            pass  # only one rule use it to check allowed http version which is not we care about.
            #ret.append('captured within')  # handle the !
        elif operators.startswith('@endsWith'):
            print('captured endsWith', operators, v)
            if v and str(v).endswith(operators[10:]):
                    ret.append('1')
            #ret.append('captured endsWith')  # handle the !
        elif operators.startswith('@detectXSS'):
            pass
            #ret.append('captured detectXSS') # handle the !
        elif operators.startswith('@detectSQLi'):
            pass
            # ret.append('captured detectSQLi')  # handle the !
        else:
            raise ValueError('Unsupported modSecurity operator found!')
    return len(ret)


def parse_variables(alerts, headers, variables):
    """
    Parse variables input, remove unsupport and duplicate items, get data for the rest ones and return in a list.
    :param variable: REQUEST_HEADERS:Range|REQUEST_HEADERS:Request-Range
    :return: a list of data
    """
    print('parse variables: %s\n%s\n%s\n' % (alerts, headers, variables))
    new_vars = []
    if not isinstance(variables, str):
        raise TypeError('bad operand type')
    list_var = variables.split('|')
    list_var.sort()  # Put ! and & items at the beginning
    for v in list_var:
        nv = v.lstrip('!&')
        if nv in DROP_LIST or nv in WAITING_LIST:
            continue
        else:
            new_vars.append(v)
    real_var = []
    print('before switch vas are', new_vars)
    if len(new_vars) != 0:
        for v in new_vars:
            if v.lstrip('!&').startswith('REQUEST_HEADERS:'):
                variable_name = v.split(':')[1]
                if len(headers) == 0:
                    real_var.append('')  # if there is no headers, return empty to match regex.
                elif v.startswith('!') and headers[variable_name]:
                    headers.pop(variable_name)
                elif v.startswith('&'):
                    real_var.append(len(headers[variable_name]))
                else:
                    real_var.append(headers[variable_name])
                continue
            elif v.lstrip('!&').startswith('REQUEST_COOKIES:'):
                cookie_name = v.split(':')[1]
                if len(headers) == 0:
                    real_var.append('')  # if there is no cookie, return empty to match regex.
                elif not headers[COOKIE]:
                    real_var.append('')  # if there is no cookie, return empty to match regex.
                elif v.startswith('!'):
                    # print(headers[COOKIE])
                    if headers[COOKIE][cookie_name]:
                        headers[COOKIE].pop(cookie_name)
                elif v.startswith('&'):
                    real_var.append(len(headers[COOKIE][cookie_name]))
                else:
                    real_var.append(headers[COOKIE][cookie_name])
                continue
            elif v.lstrip('!&') == 'REQUEST_HEADERS':
                whole_header = ''
                for (key, value) in headers.items():
                    if key == COOKIE and headers[key]:
                        whole_cookie = ''
                        for c_key, c_value in headers[key].items():
                            whole_cookie = 'Cookie:%s=%s;%s' % (c_key, c_value, whole_cookie)
                        whole_header = '%s,%s' % (whole_cookie, whole_header)
                    else:
                        whole_header = '%s:%s,%s' % (key, value, whole_header)
                real_var.append(whole_header)
                continue
            elif v == 'REQUEST_HEADERS_NAMES':
                if len(headers) == 0:
                    real_var.append('')  # if there is no header, return empty to match regex.
                    continue
                real_var.append(','.join(headers.keys()))
                continue
            elif v == 'REQUEST_COOKIES_NAMES':
                if len(headers[COOKIE]) == 0:
                    real_var.append('')  # if there is no cookie, return empty to match regex.
                    continue
                else:
                    real_var.append(','.join(headers[COOKIE].keys()))
            elif v == 'ARGS_GET' or v == 'ARGS':
                print(v, alerts.args_get)
                print('captured args: %s' % alerts.args_get)
                real_var.append(alerts.args_get)
            elif v == 'ARGS_GET_NAMES' or v == 'ARGS_NAMES':
                print('captured args_names: %s' % alerts.args_get_names)
                if len(alerts.args_get_names) == 0:
                    real_var.append('')  # if there is no args, return empty to match regex.
                    continue
                real_var.append(','.join(alerts.args_get_names))
            elif v == 'REQUEST_URI':
                real_var.append(alerts.uri)
            elif v == 'REQUEST_LINE':
                real_var.append(alerts.request)
            elif v == 'RESPONSE_STATUS':
                print('captured RESPONSE_STATUS: %s' % alerts.status)
                real_var.append(alerts.status)
            elif v == 'REQUEST_PROTOCOL':
                real_var.append(alerts.request_protocol)
            elif v == 'QUERY_STRING':
                real_var.append(alerts.query_string)
            elif v == 'REQUEST_BASENAME':
                real_var.append(alerts.request_basename)
            elif v == 'REQUEST_FILENAME':
                real_var.append(alerts.request_filename)
            elif v == 'REQUEST_METHOD':
                real_var.append(alerts.method)
            elif v == 'REQUEST_URI_RAW':
                real_var.append(alerts.request_uri_raw)

    #'request_uri_raw', 'method', 'args_get', 'args_get_names', 'request_filename'
    print('return parsed vars are : ', real_var)
    return real_var


def get_data(id, db_name):
    """
    Get all data by id and return 2 list for both alerts and request_headers table
    :param id:
    :return: 2 list
    """
    if os.path.isfile(db_name) is False:
        return -1
    else:
        header_result = defaultdict(lambda: '')
        alerts_result = []
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        cursor = c.execute('select id,ip,remoteName,request,uri,status,host,time,state,msg '
                           'from alerts where id=%d' % id)
        for row in cursor:
            alerts_result = list(row)
        cursor = c.execute('select * from request_headers where alert_id=%d' % id)
        for row in cursor:
            if row[2] == COOKIE:
                cookie_dict = defaultdict(lambda: '')
                cookie_list = row[3].strip(';').split(';')
                for cookie in cookie_list:
                    c_list = cookie.strip().split('=')
                    cookie_dict[c_list[0]] = c_list[1]
                header_result[row[2]] = cookie_dict
            else:
                header_result[row[2]] = row[3]
        cursor.close()
        c.close()
        conn.close()
    request_uri_raw = ''
    matchmsg = re.match(r'\'(https?://.*)\' not allowed', alerts_result[9])
    if matchmsg:
        request_uri_raw = matchmsg.group(0)
    alerts_result[9] = request_uri_raw
    request_vars = get_vars_from_request(alerts_result[3])
    Alert = namedtuple('Alert', ['id', 'ip', 'remotename', 'request', 'uri', 'status', 'host', 'time', 'state'
                                 , 'request_uri_raw', 'method', 'args_get', 'args_get_names', 'request_filename',
                                 'request_basename', 'query_string', 'request_protocol'])
    alerts_result.extend(request_vars)
    alert = Alert._make(alerts_result)
    print('testtest', alert)
    return alert, header_result
#get_data(114791, "alertsbig.db")



# alert, header = get_data(114791, db_name)
# dict_rules = get_all_rules(ZY_RULE_FILE)
# parse_variables(alert,header,dict_rules['920201'].variables)


if __name__ == '__main__':
    #get_all_operator_types(ZY_RULE_FILE)
    result_file_name = "result_modsecurity.txt"
    dict_rules, DATA_FILES = get_all_rules(ZY_RULE_FILE)
    result = []
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    cursor = c.execute('select count(*) from alerts ')
    for row in cursor:
        rec_num = row[0]
    for i in range(54890, 54891+1):  # (114791, 114791+1):  # 114791
        k_result = []
        alert, header = get_data(i, db_name)
        print(alert, header)
        for k in dict_rules.keys():
            print(i, '#####', k)
            rule_result = execute_rule(alert, header, dict_rules[k])  # 930100
            if rule_result:
                k_result.append(k)  # 930100
        if len(k_result) > 0:
            result.append(k_result)
            z = open(result_file_name, "a", encoding='UTF-8')
            z.write("%s\t%s\t%s\t%s\n" % (i, k_result, alert, header))
            z.close()
        else:
            result.append('')
    print('result is : %s' % result)
    z = open(result_file_name, "a", encoding='UTF-8')
    z.write('result is : %s' % result)
    z.close()

