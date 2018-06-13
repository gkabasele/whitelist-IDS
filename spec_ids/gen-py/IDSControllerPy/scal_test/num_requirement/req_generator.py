import os
import random
from jinja2 import Environment, FileSystemLoader

PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_ENVIRONMENT = Environment(
         autoescape=False,
         loader=FileSystemLoader(os.path.join(PATH, "templates")),
         trim_blocks=False)

num_comp = ["<", ">", "<=", ">="]
numeric = ["tank1", "wagoncar", "tankfinal", "silo2"]
boolean = ["valvecharcoal", "wagonend", "motor1", "motor2"]


def render_template(template_filename, context):
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)

def generate_requirement():
    kind = random.randint(0, 100)
    if kind % 2 == 0:
        var = numeric[random.randint(0, len(numeric)-1)]
        comp = num_comp[random.randint(0, len(num_comp)-1)]
        value = random.randint(0, 100)
        return "( %s %s %s )"%(var, comp, value)
    else:
        index = random.randint(0, len(boolean)-1)
        i = (index + 1) % len(boolean)
        vara = boolean[index]
        varb = boolean[i]
        return "( %s = 1 & %s = 1)" % (vara, varb)


def create_content(size, conjuction=1):
    content = []
    for i in xrange(size):
        req = ""
        for i in xrange(conjuction):
            if i == 0:
                req.join(generate_requirement())
            else:
                req.join(" & %s" % (generate_requirement()))
        content.append(req)
    return content

def create_requirement_files(dirname):

    for i in [5, 50, 100, 150, 200]:
        content = create_content(i)
        context = {"requirements":content}
        name = "%s/req_%s.yml" % (dirname, i)
        with open(name, 'w') as f:
            script = render_template("req.yml", context)
            f.write(script)

def create_size_requirement_files(dirname):

    for i in xrange(0, 25, 5):
        i = 1 if i == 0 else i
        content = create_content(i)
        print content
        context = {"requirements":content}
        name = "%s/req_%s.yml" % (dirname, i)
        with open(name, 'w') as f:
            script = render_template("req.yml", context)
            f.write(script)

def main():
    #create_requirement_files("num_requirement")
    create_size_requirement_files("size_requirement")

if __name__ == "__main__":
    main()
