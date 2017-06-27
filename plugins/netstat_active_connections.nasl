#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58651);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/02 17:53:33 $");

  script_name(english:"Netstat Active Connections");
  script_summary(english:"Find active connections with netstat");

  script_set_attribute(
    attribute:"synopsis",
    value:"Active connections are enumerated via the 'netstat' command."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin runs 'netstat' on the remote machine to enumerate all
active 'ESTABLISHED' or 'LISTENING' tcp/udp connections."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_dependencies("netstat_portscan.nasl", "wmi_netstat.nbin");

  exit(0);
}

include('misc_func.inc');
include('global_settings.inc');
include('network_func.inc');

netstat = get_kb_item('Host/netstat');
if (isnull(netstat))
  netstat = get_kb_item('Host/Windows/netstat_ano');
if (isnull(netstat))
  netstat = get_kb_item('Host/Windows/netstat_an');
if (isnull(netstat))
  exit(0, 'No netstat output was found in the KB.');

public_ips = make_array();
lines = split(netstat, keep:FALSE);

report_info = "";

write_output = TRUE;

foreach line (lines)
{
  if ("active" >< tolower(line) && "socket" >< tolower(line))
    write_output = FALSE;

  if (write_output)
        report_info += line + '\n';
}

if (report_info != "")
{
  if(report_verbosity > 0)
  {
    report = '\nNetstat output :\n';
    report += report_info;
    security_note(extra: report, port:0);
  }
  else security_note(0);
  exit(0);
} 
else exit(0, "No active connections were discovered.");
