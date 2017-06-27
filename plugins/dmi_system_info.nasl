#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35351);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2016/08/17 15:31:18 $");
 script_name(english: "System Information Enumeration (via DMI)");
 script_set_attribute(attribute:"synopsis", value:
"Information about the remote system's hardware can be read.");
 script_set_attribute(attribute:"description", value:
"Using the SMBIOS (aka DMI) interface, it was possible to retrieve
information about the remote system's hardware, such as its product
name and serial number.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/12");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_summary(english: "Extract system information from dmidecode");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english: "General");
 script_dependencies("bios_get_info_ssh.nasl");
 script_require_keys("Host/dmidecode");
 exit(0);
}

if (!defined_func("nasl_level") || nasl_level() < 6000) exit(0, "Nessus older than 6.x");

##
# Creates DMI handle object with to_str() method.
##
object dmi_handle
{
  var handle_name;
  var handle_entries = make_array();

  # constructor
  function dmi_handle()
  {
     if(!isnull(_FCT_ANON_ARGS[0]))
        handle_name = _FCT_ANON_ARGS[0];
  }
  public function set_handle_name () { handle_name = _FCT_ANON_ARGS[0]; }
  public function add_handle_entry (name, value)
  {
    handle_entries[name] = value;
  }

  ##
  # Converts object to string
  #
  # @return string of object information
  ##
  public function to_str()
  {
    var ret_str = '';
    var key, max_len;
    ret_str += handle_name;
    foreach key (keys(handle_entries))
      if(strlen(key) > max_len) max_len = strlen(key);
    foreach key (keys(handle_entries))
      ret_str += '\n  ' + key + crap(data:' ', length:max_len - strlen(key)) + ' : ' + handle_entries[key];
    return ret_str;
  }
}

buf = get_kb_item("Host/dmidecode");
if ("System Information" >!< buf) exit(0, "No DMI system information.");

elements = make_array(
  'System Information',   make_list('Manufacturer', 'Product Name', 'Serial Number', 'Family', 'Version'),
  'Chassis Information',  make_list('Manufacturer', 'Type', 'Lock', 'Serial Number', 'Version')
);

section = '';
current_section = '';
summary = {};

lines = split(buf, keep: 0);

foreach line (lines)
{
  section = eregmatch(string: line, pattern: '^.*Information$');

  if (! isnull(section))
  {
    # start new section
    if (section != current_section)
    {
      current_section = section[0];
      # write new dmi_handle for this section
      dmi_handle = new("dmi_handle", current_section);
      continue;
    }
  }

  # skip empty lines
  if (! strlen(line))
  {
    continue;
  }

  # not in a section or no keys to find for this section
  if (isnull(current_section) || isnull(elements[current_section]))
  {
    continue;
  }

  foreach element (elements[current_section])
  {
    unspaced_section = str_replace(string: current_section, find: ' ', replace: '');
    unspaced_element = str_replace(string: element, find: ' ', replace: '');

    pattern = strcat('^[ \t]+', element, '[ \t]*:[  \t]*([^ \t].*)');
    match = eregmatch(string: line, pattern: pattern);
    if (! isnull(match))
    {
      dmi_handle.add_handle_entry(name: element, value: match[1]);
      # update section dmi summary table
      summary[current_section] = dmi_handle.to_str() + '\n';
      # set kb item for section/element
      set_kb_item(name: strcat('DMI/System/', unspaced_section, '/', unspaced_element), value: match[1]);

      # but for backwards compatability - keep the key kb entry
      set_kb_item(name: strcat('DMI/System/', unspaced_element), value: match[1]);
    }
  }
}

if (! summary) exit(1, "Empty DMI system information.");

report = '';
foreach section (summary)
{
  report += section + '\n';
}

security_note(port: 0, extra: report);