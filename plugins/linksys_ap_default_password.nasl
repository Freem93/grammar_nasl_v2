#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11522);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_osvdb_id(821);

  script_name(english:"Linksys Router Default Password (admin)");
  script_summary(english:"Tests for the linksys default account");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to log on the remote device with a default password.");
  script_set_attribute(attribute:"description", value:
"The remote Linksys device has its default password ('admin') set.
An attacker may connect to it and reconfigure it using this account.");
  script_set_attribute(attribute:"solution", value:
"Connect to this port with a web browser, and click on the 'Password'
section to set a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  exit(0);
}

# The script code starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

n = 0;
login[n] = "";		pass[n++] = "admin";
login[n] = "admin";	pass[n++] = "admin";

port = get_http_port(default:80, embedded: 1);

linksys = 0;

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if (! egrep(pattern: "^HTTP/[01.]+ +401 ", string: res))
 exit(0, build_url(port:port, qs: "/") + " is not protected.");

if ('WWW-Authenticate: Basic realm="Linksys' >< res) linksys ++;

for (i = 0; i < n; i ++)
{
  r = http_send_recv3(port: port, method: 'GET', item: '/',
        username: login[i], password: pass[i], exit_on_fail: 1);
  if (r[0] =~  "^HTTP/[01.]+ 200 ")
  {
    if (! linksys)
      if ("Linksys" >< r[2])
        linksys ++;

    if (report_paranoia < 2 && ! linksys)
      exit(1, "The remote web server on port "+port+" does not look like Linksys.");
    e = strcat(
'\nIt was possible to log with the following credentials :',
'\n  Username : ', login[i],
'\n  Password : ', pass[i], '\n');
    security_hole(port:port, extra: e);
    exit(0);
  }
}

if (linksys) audit(AUDIT_LISTEN_NOT_VULN, "Linksys web server", port);
else exit(0, "The web server listening on port "+port+" is not affected.");
