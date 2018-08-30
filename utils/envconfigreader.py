import os
import ConfigParser

config_file = os.environ['CONFIG_FILE']


# Returns the property from cfg file
def get_property(section, property):

    config = ConfigParser.ConfigParser()
    config.read(config_file)
    return config.get(section, property)


# Returns all properties under a section from cfg file
def get_all_properties_from_section(section):

    config = ConfigParser.ConfigParser()
    config.read(config_file)
    return dict(config.items(section))
