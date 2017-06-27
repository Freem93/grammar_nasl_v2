#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73104);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2014-2321");
  script_bugtraq_id(65962);
  script_osvdb_id(104187);
  script_xref(name:"CERT", value:"600724");

  script_name(english:"ZTE F460 / F660 Cable Modems web_shell_cmd.gch Administrative Backdoor");
  script_summary(english:"Checks for backdoor on device");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote device has a backdoor that allows administrative commands to
be executed without authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to access the 'web_shell_cmd.gch' script on the device,
which is a backdoor that allows administrative commands to be run on the
device without authentication."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"There are no known vendor updates for this issue.  As a workaround,
delete the backdoor script on the device."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zte:f660");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zte:f460");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);

server_name = http_server_header(port:port);
if ('Mini web server 1.0 ZTE' >!< server_name) audit(AUDIT_NOT_DETECT, 'ZTE Web Server', port);

res = http_send_recv3(item         : '/web_shell_cmd.gch',
                      method       : "GET",
                      port         : port,
                      exit_on_fail : TRUE);

report = '';

if (
  'web_shell_cmd.gch' >< res[2] &&
  'please input shell command' >< res[2] &&
  'ZTE Corporation' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n' + 'Nessus was able to access a backdoor by visiting the following URL :' +
      '\n' +
      '\n' + '  ' + build_url(port:port, qs:'/web_shell_cmd.gch') + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ZTE Web Server", port);
