#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17367);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/08/29 21:03:58 $");

 script_name(english:"Fortinet FortiGate Web Console Management Detection");
 script_summary(english:"Checks for the Fortinet Fortigate management console.");

 script_set_attribute(attribute:"synopsis", value:
"A firewall management console is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"A Fortinet FortiGate Firewall is running on the remote host, and
connections are allowed to its web-based console management port.

Letting attackers know that you are using this software will help them
to focus their attack or will make them change their strategy. In
addition to this, an attacker may set up a brute-force attack against
the remote interface.");
 script_set_attribute(attribute:"see_also", value:"https://www.fortinet.com/products/fortigate/");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 443);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, embedded:TRUE);

app_name = "FortiOS Web Interface";
install_found = FALSE;
version = NULL;

# Legacy check first.
url = "/system/console?version=1.5";
pattern = "Fortigate Console Access";

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:FALSE
  );

if ("200" >< res[0] && preg(string:res[2], pattern:pattern, multiline:TRUE, icase:TRUE)) install_found = TRUE;

# FortiOS 3.x check next.
if (!install_found)
{
  url = "/images/login_top.gif";
  image_hash = "f328d4514fe000a673f473e318e862fb";

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
    );

  if ("200" >< res[0] && hexstr(MD5(res[2])) == image_hash)
  {
    install_found = TRUE;
    version = "3.0 or earlier";
  }
}

# FortiOS 4.x, 5.x check next.
if (!install_found)
{
  url = "/images/logon_merge.gif";
  image_hash = "3955ddaf1229f63f94f4a20781b3ade4";

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
    );

  if ("200" >< res[0] && hexstr(MD5(res[2])) == image_hash)
  {
    install_found = TRUE;
    version = "4.0 or 5.0";
  }
}

# Add install to KB and report.
if (install_found)
{
  installs = add_install(installs: installs, dir: '/', appname: "fortios_ui", ver:version, port: port);
  set_kb_item(name:"www/fortios", value:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

if (report_verbosity > 0)
{
  report = get_install_report(port:port, installs: installs, item: '/', display_name: app_name);
  security_note(port:port, extra:report);
}
else security_note(port);
