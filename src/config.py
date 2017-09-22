import yaml

class Config:
    def __init__(self, data=None, parent=None):
        self.data = data
        self.parent = parent
    
    def __getitem__(self, key):
        if isinstance(self.data[key], (dict, list)):
            return Config(data=self.data[key], parent=self)
        return self.data[key]
    
    def __setitem__(self, key, value):
        self.data[key] = value
        self.save()
    
    def __delitem__(self, key):
        del self.data[key]
        
    def __iter__(self):
        return iter(self.data)
    
    def __contains__(self, item):
        return item in self.data
    
    def __str__(self):
        return str(self.data)
    
    def __repr__(self):
        return 'Config(data={})'.format(repr(self.data))
    
    def __getattr__(self, name):
        return getattr(self.data, name)
    
    def load(self, path):
        with open(path, 'r') as config_file:
            data = yaml.load(config_file.read())
        self.path = path
        self.data = data
    
    def save(self, path = None):
        if self.parent:
            return self.parent.save(path)
        if not path:
            path = self.path
        try:
            with open(path, 'w') as config_file:
                config_file.write(yaml.dump(self.data, default_flow_style=False))
        except:
            logging.error('Unable to open "{}" file.'.format(options.config))
