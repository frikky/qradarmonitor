#fields = "?fields=id%2C%20categories%2C%20severity%2C%20description%2C%20source_network"
#filters = "&filter=status%20%3D%20%22OPEN%22"

fields = ""
filters = ""

class Customer(object):
    def __init__(self, name, token, target, version, rules, ref_list, cert, domain, ID = 0):#, token, latest):
        self.header = {
            'Range': 'items=0-49',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Version': '',
            'SEC': ''
        }

        self.name = name
        self.target = target
        self.version = version
        self.rules = rules
        self.ID = ID 
        self.ref_list = ref_list
        self.cert = cert
        self.domain = domain

        self.fields = fields
        self.filters = filters

        self.header['Version'] = str(version)
        self.header['SEC'] = str(token)

        self.fail_counter = 0
    
        self.target_path = "https://%s/api/siem/offenses%s%s" % (target, self.fields, self.filters)
        self.new_version = True
