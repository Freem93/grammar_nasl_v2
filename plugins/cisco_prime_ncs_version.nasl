#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66860);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/11 15:32:22 $");

  script_name(english:"Cisco Prime Network Control System Version");
  script_summary(english:"Gets the NCS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"It is possible to obtain the version of the remote appliance."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Cisco Prime Network Control System (NCS), a
network management system. 

It is possible to get the Prime NCS version number via SSH or SNMP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps11686/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_network_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "snmp_software.nasl");
  script_require_ports("Host/Cisco/show_ver", "SNMP/hrSWInstalledName");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

##
# Saves the Prime NCS version in the KB, generates plugin output, and exits
#
# @anonparam ver Prime NCS version number
# @anonparam source protocol used to obtain the version
# @remark this function never returns
##
function report_and_exit()
{
  local_var ver, source, report;
  ver = _FCT_ANON_ARGS[0];
  source = _FCT_ANON_ARGS[1];
  set_kb_item(name:"Host/Cisco/Prime_NCS/Version", value:ver);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source + 
      '\n  Version : ' + ver +
      '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH

is_prime_ncs = get_kb_item("Host/Cisco/Prime_NCS");
showver = get_kb_item("Host/Cisco/show_ver");
if (is_prime_ncs && !isnull(showver))
{
  match = eregmatch(string:showver, pattern:"Version : ([\d.]+)");
  if (!isnull(match))
  {
    report_and_exit(match[1], 'SSH');
    # never reached
  }
}

# 2. SNMP

software = get_kb_item("SNMP/hrSWInstalledName");
if (!isnull(software))
{
  match = eregmatch(string:software, pattern:"NetworkControlSystem-([\d.]+)-1");
  if (!isnull(match))
  {
    report_and_exit(match[1], 'SNMP');
    # never reached
  }
}

if (is_prime_ncs)
  exit(1, 'Unable to determine Prime NCS version number obtained via SSH.');
else
  exit(0, 'The Prime NCS version is not available (the remote host may not be Prime NCS).');
