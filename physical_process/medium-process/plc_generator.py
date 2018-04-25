import os
from jinja2 import Environment, FileSystemLoader
from constants import *

PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_ENVIRONMENT = Environment(
         autoescape=False,
         loader=FileSystemLoader(os.path.join(PATH, TEMPLATES_DIR)),
         trim_blocks=False)


def render_template(template_filename, context):
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)


def create_plc_scripts():

    for k,v in varmap.iteritems():
        context = { "name_plc" : k, "variable_type" : v} 
        fname = PLCS_DIR + "/script_plc_"+ k +".py"
        with open(fname, 'w') as f:
            plc_script = render_template('script_plc_template.py', context)
            f.write(plc_script)
            
def main():
    create_plc_scripts()

########################################

if __name__ == "__main__":
    main()

