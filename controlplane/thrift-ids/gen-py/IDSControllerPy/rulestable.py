def verify(func):
    def wrapper(self, *args, **kwargs):
        a = list(args)
        assert len(a[0]) == self.num_fields, "Number of fields for the rule does not match"
        return func(self, *args)
    return wrapper

class RuleTables():
    '''
        rule : fields used for matching, ex :5-tuples (srcip, sport, dstip, dport, proto)
        resp_switch : list of switch concerned by this rule
        num_entry : dict {switch_id : num_entry} where entry is the id of the rule in
                  the table
    '''

    def __init__(self, num_fields) :
        self.rules = {}
        self.num_fields = num_fields 

    ''' 
        rule : fields used for matching
        switch_id : datapath id of switch containing the flow
        num_entry : number entry of flow in the flow table on the switch
        rule_type: ALLOW rule or DROP (for now, later REDIRECT,CLONED,...)
        wl_orig: Was the rule in the original whitelist

        Add rule to the table
    '''
    @verify
    def add_rule(self, rule, switch_id, num_entry, rule_type, wl_orig=False):
        if rule not in self.rules:
            self.rules[rule] = {switch_id : (num_entry,rule_type, wl_orig)}
        elif switch_id not in self.rules[rule]:
            self.rules[rule][switch_id] = (num_entry, rule_type, wl_orig)
    '''
        rule : fields used for matching
        switch_id : datapath id of switch containing the flow

        delete rule in the table
    '''

    @verify
    def delete_rule(self, rule, switch_id):
        self.rules[rule].pop(switch_id, None)
        if len(self.rules[rule]) == 0:
            self.rules.pop(rule,None)

    '''
        rule : fields used for matching
        switch_id : datapath id of switch containing the flow
        
        update rule entry number from the table
    '''
    @verify
    def update_rule(self, rule, switch_id, num_entry, rule_type):
        wl_orig = self.get_origin_entry(rule, switch_id) 
        self.rules[rule][switch_id] = (num_entry, rule_type, wl_orig)
        
    '''
        rule : fields used for matching
        
        return the list of switchs containing a rule for this fields
    '''
    @verify
    def rule_to_switches(self, rule):
        if rule in self.rules:
            return self.rules[rule].keys()

    '''
        rule : fields used for matching
        return the entry number of the rule in switch with switch_id
    '''
    @verify
    def get_num_entry(self, rule, switch_id):
        if rule in self.rules and switch_id in self.rules[rule]:
            return self.rules[rule][switch_id][0]
    '''
        rule : fields used for matching
        return the type (ALLOW,DROP) the rule in switch with switch_id
    '''
    @verify
    def get_type_entry(self, rule, switch_id):
        return self.rules[rule][switch_id][1]

    @verify
    def get_origin_entry(self, rule, switch_id):
        return self.rules[rule][switch_id][2]

    @verify
    def is_rule_installed(self, rule):
        return rule in self.rules

    def get_rules(self):
        return self.rules

    def dump_table(self):
        print "---------"
        print "RuleTable"
        for rule, sw in self.rules.iteritems():
            print rule,":"
            for sw_id, entry_handle in sw.iteritems():
                print "\tSwitch_id: ",sw_id," Entry: ",entry_handle , "\n"
        print "---------" 


