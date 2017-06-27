#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88145);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/27 21:09:09 $");

  script_name(english:"Host Unique Identifiers");
  script_summary(english:"Summarizes all unique identifiers found.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has one or more unique identifiers used by various
endpoint management systems.");
  script_set_attribute(attribute:"description",value:
"Nessus has discovered one or more unique identifiers used to tag or
track the remote system.");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies(
    "mcafee_epo_agent_installed.nbin",
    "mcafee_epo_agent_installed_nix.nbin",
    "savce_installed.nasl"
  );
  script_require_keys("Host/Identifiers");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");

# Identifiers are stored as Host/Identifiers/<Name of Endpoint Management Product>=<Some Unique ID>
identities = get_kb_list_or_exit("Host/Identifiers/*");
report = 'The following Identifiers were discovered :\n';
rootkb = 'Host/Identifiers/';

foreach key (keys(identities))
{
  product = ereg_replace(pattern:rootkb, replace:'', string:key);
  report += '\n';
  report += '  Product  : '+product+'\n';
  report += '  Identity : '+identities[key]+'\n';
}

security_note(extra:report, port:0);
