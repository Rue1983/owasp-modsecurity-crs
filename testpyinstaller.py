import requests
import pygal
from collections import Counter
import matplotlib.pyplot as plt
from pywaffle import Waffle

#print('hello')
#print('test', r[9999])
# gather data for classify by category
def classify(result_list):
    new_list = []
    for item in result_list:
        new_list.append(item[:3])
    print(new_list)
    if len(set(new_list)) == 1:
        return new_list[0]
    lc = Counter(new_list)
    #if len(lc) > 1:
    print(list(lc.keys())[list(lc.values()).index(max(lc.values()))])
    return list(lc.keys())[list(lc.values()).index(max(lc.values()))]

#dict_result = {913:0, 920:0, 921:0, 930:0, 931:0, 932:0, 933:0, 941:0, 942:0, 943:0, 950:0}
dict_rulename = {913:'Scanner Detection', 920:'Protocol Enforcement', 921:'Protocol Attack', 930:'Local File Execution',
                 931:'Remote File Inclusion', 932:'Remote Code Execution', 933:'PHP Injection', 941:'XSS',
                 942:'SQL Injection', 943:'Session Fixation', 950:'Disclosure Attack'}


def get_owasp_attack_type(result):
    ret = {913: 0, 920: 0, 921: 0, 930: 0, 931: 0, 932: 0, 933: 0, 941: 0, 942: 0, 943: 0, 950: 0}
    for i,r in enumerate(result):
        if not r:
            continue
        else:
            attack_type = int(classify(r))
            print(attack_type)
            ret[attack_type] = ret[attack_type] + 1
    ret = {key:ret[key] for key in ret.keys() if ret[key]}
    print(ret)
    return ret


def owasp_attack_type_bar(result):
    dict_result = get_owasp_attack_type(result)
    bar_chart = pygal.Bar(truncate_legend=-1, human_readable=True)
    bar_chart.title = 'Alerts by OWASP attack types'
    for k,v in dict_result.items():
        if v == 0:
            continue
        bar_chart.add(dict_rulename[k],v)
    bar_chart.render()
    bar_chart.render_to_file('OWASP_attack_types.svg')
    

def owasp_attack_type_waffle(dict_result):
    dict_result = get_owasp_attack_type(result)
    print('---- before ', dict_result)
    total_number = sum(dict_result.values())

    dict_result = {dict_rulename[key]: int('%d' % (dict_result[key]/total_number*100)) for key in dict_result.keys()
                   if dict_result[key] >= total_number/100}
    print('-----', dict_result)
    #for k,v in dict_result.items():
    #    dict_result[k] = '%d' % (dict_result[k]/total_number*100)
    chart_values = list(dict_result.values())
    print(chart_values)
    # The values are rounded to 10 * 5 blocks
    fig = plt.figure(
        FigureClass=Waffle,
        rows=10,
        columns=10,
        values=dict_result,
        legend = {'loc': 'lower left', 'bbox_to_anchor': (0, 1.1)}
    )
    plt.show()


def test():
    plt.savefig('owasp_types_waffle.png', dpi=150)
    data = {'Democratic': 48, 'Republican': 46, 'Libertarian': 3}
    fig = plt.figure(
        FigureClass=Waffle,
        rows=5,
        values=data,
        legend={'loc': 'lower left', 'bbox_to_anchor': (0, 1.1)}
    )
    plt.show()

#classify(['920230', '942431', '942432'])
#get_owasp_attack_type(result)
#owasp_attack_type_bar(result)
#owasp_attack_type_waffle(get_owasp_attack_type(result))
test()



