#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51859);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/25 20:53:07 $");

  script_name(english:"OS Identification : SNMP hrSWInstalledName");
  script_summary(english:"Identifies devices based on SNMP hrSWInstalledName");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based an SNMP
query of its hrSWInstalledName object.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified by querying its
hrSWInstalledName object using SNMP.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_dependencies("snmp_software.nasl");
  script_require_keys("SNMP/hrSWInstalledName");

  exit(0);
}

soft = get_kb_item("SNMP/hrSWInstalledName");
if (! soft) exit(0, "SNMP/hrSWInstalledName is not set.");

if (egrep(string: soft, pattern: '^(yast2|susehelp|suseRegister)-'))
{
  set_kb_item(name:"Host/OS/hrSWInstalledName", value:"SuSE");
  set_kb_item(name:"Host/OS/hrSWInstalledName/Confidence", value:98);
  set_kb_item(name:"Host/OS/hrSWInstalledName/Type", value:"general-purpose");
  exit(0);
}
if (egrep(pattern:'^HP ProLiant iLO ([0-9]+) ', string:soft))
{
  os = "HP Integrated Lights Out";
  foreach line (split(soft, keep:FALSE))
  {
    match = eregmatch('^HP ProLiant iLO ([0-9]+) ', string:line);
    if (match)
    {
      os += ' ' + match[1];
      break;
    }
  }
  set_kb_item(name:"Host/OS/hrSWInstalledName", value:os);
  set_kb_item(name:"Host/OS/hrSWInstalledName/Confidence", value:98);
  set_kb_item(name:"Host/OS/hrSWInstalledName/Type", value:"embedded");

  exit(0);
}
