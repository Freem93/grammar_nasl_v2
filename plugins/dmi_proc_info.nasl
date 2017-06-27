#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(45432);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2016/02/25 17:20:33 $");

 script_name(english:"Processor Information (via DMI)");
 script_summary(english:"Extract processor information from dmidecode.");
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to read information about the remote system's
processor.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to retrieve information about the remote system's
hardware, such as its processor type, by using the SMBIOS (aka DMI)
interface.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

 script_family(english: "General");
 script_dependencies("bios_get_info_ssh.nasl");
 script_require_keys("Host/dmidecode");
 exit(0);
}

include("global_settings.inc");

buf = get_kb_item("Host/dmidecode");
if (isnull(buf)) exit(1, "The 'Host/dmidecode' KB setting is missing.");
if ("Processor Information" >!< buf) exit(0, "No DMI processor information.");

# Max Speed, Current Speed and Flags are not reliable
keys = make_list("Type", "Family", "Manufacturer", "Version", 
     "Current Speed", "External Clock", "Status");

sections = split(buf, sep:'Processor Information', keep:FALSE);
cpus = make_list();
num_cpu = 0;

for (i = 1; i < max_index(sections); i++) # start at 1 to skip over anything before the 1st CPU info section
{
  lines = split(sections[i], keep: 0);
  cpu = make_array();

  foreach l (lines)
  {
    foreach k (keys)
    {
      pat = strcat('^[ \t]+', k, '[ \t]*:[  \t]*([^ \t].*)');
      v = eregmatch(string: l, pattern: pat);
      if (! isnull(v)) cpu[k] = v[1];
    }
  }

  # only report on something that looks like an actual CPU
  if (
     cpu['Manufacturer']           == '000000000000' ||
     cpu['Version']                == '00000000000000000000000000000000' ||
     tolower(cpu['Manufacturer'])  == 'Not Specified' ||
     tolower(cpu['Version'])       == 'Unknown Processor' ||
     tolower(cpu['Current Speed']) == 'unknown' ||
     tolower(cpu['Status'])        == 'unpopulated' ||
     tolower(cpu['Status'])        == 'populated, disabled by bios'
  )
    continue;
  else
    cpus[num_cpu++] = cpu;
}

if (max_index(cpus) == 0) exit(1, "Empty DMI processor information.");
else if (max_index(cpus) == 1) s = '';
else s = 's';

report = '\nNessus detected ' + max_index(cpus) + ' processor'+s+ ' :\n';

for (i = 0; i < max_index(cpus); i++)
{
  report += '\n';
  values = cpus[i];
  foreach k (keys(values))
  {
   k2 = str_replace(string: k, find: " ", replace: "");
   set_kb_item(name: strcat("DMI/Processor/", i, "/", k2), value: values[k]);
   report = strcat( report, k,
              crap(data: ' ', length: 15-strlen(k)), ' : ', values[k], '\n');
  }
}

security_report_v4(port: 0, extra:report, severity:SECURITY_NOTE);
