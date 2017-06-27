#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79235);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/13 19:54:52 $");

  script_name(english:"Unprotected Telnet Service");
  script_summary(english:"Checks telnet banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote Telnet service is unprotected.");
  script_set_attribute(attribute:"description", value:
"An unprotected Telnet service is listening on this port.  A remote
attacker can utilize this to execute commands on the host.");
  script_set_attribute(attribute:"solution", value:"Configure an authentication mechanism or restrict access to the service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

banner = get_telnet_banner(port:port);
if (strlen(banner) == 0) audit(AUDIT_NO_BANNER, port);

shell = '';

if (
  'for a list of built-in commands' >< banner &&
  'BusyBox v' >< banner && 'login:' >!< banner &&
  banner =~ "[#$][\s\n]*$"
) shell = 'BusyBox';
else if (
  'Pocket CMD v' >< banner &&
  "Windows CE Telnet" >< banner &&
  banner =~ "\>[\s\n]*$"
) shell = 'Windows CE Pocket CMD';
else if (
  "Welcome to MontaVista" >< banner && 
  banner =~ "root@~#[\s\n]*$"
) shell = "Monta Vista Linux";
else if (
  "Sash command shell" >< banner && 
  banner =~ "/>[\s\n]*$"
) shell = "Sash";

if (shell != '')
{
  if (report_verbosity > 0)
  {
    report =  '\n' + 'An unprotected ' + shell + ' shell with the following banner was detected :' +
              '\n' +
              '\n' + banner + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Telnet Server', port);
