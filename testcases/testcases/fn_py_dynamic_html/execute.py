from datetime import datetime
from random import sample
from os import path

from jinja2 import Template

SCRIPT_DIR = path.abspath(path.join(path.dirname(__file__)))

def handler(event):
    name = event.get('username')
    size = event.get('random_len')
    cur_time = datetime.now()
    random_numbers = sample(range(0, 1000000), size)
    template = Template(open(path.join(SCRIPT_DIR, 'template.html'), 'r').read())
    html = template.render(username = name, cur_time = cur_time, random_numbers = random_numbers)
    return {'result': html}

fn_name = 'testcases/fn_py_dynamic_html'
