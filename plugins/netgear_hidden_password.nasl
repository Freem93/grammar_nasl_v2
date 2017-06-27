#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12258);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2017/05/24 13:36:52 $");

 script_cve_id("CVE-2004-2556", "CVE-2004-2557");
 script_bugtraq_id(10459);
 script_osvdb_id(6743);

 script_name(english:"NETGEAR Wireless Access Point Hardcoded Default Password");
 script_summary(english:"NETGEAR Hidden Password Check.");

 script_set_attribute(attribute:"synopsis", value:
"The remote network device can be accessed using an undocumented
administrative account.");
 script_set_attribute(attribute:"description", value:
"NETGEAR ships at least one device with a built-in administrator
account. This account cannot be changed via the configuration
interface and enables a remote attacker to control the NETGEAR device.

To duplicate this error, simply point your browser to a vulnerable
machine, and log in (when prompted) with :

  userid = super
  password = 5777364

or :

  userid = superman
  password = 21241036");
 # http://liveweb.archive.org/http://archives.neohapsis.com/archives/bugtraq/2004-06/0036.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43b54e1d");
 # http://liveweb.archive.org/http://archives.neohapsis.com/archives/bugtraq/2004-06/0077.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d45141a1");
 # https://slashdot.org/story/04/06/08/1319206/netgears-amusing-fix-for-wg602v1-backdoor
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24193259");
 script_set_attribute(attribute:"solution", value:
"Contact vendor for a fix. As a temporary workaround, disable the web
server or filter the traffic to the NETGEAR web server via an upstream
firewall.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/h:netgear:wg602");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("netgear_www_detect.nbin");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_keys("installed_sw/Netgear WWW");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

get_install_count(app_name:"Netgear WWW", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Netgear WWW", port:port);

res = http_get_cache(port: port, item: "/", exit_on_fail: TRUE);
if (!pgrep(string:res, pattern:"HTTP/.* 40[13] "))
{
  exit(0, "Start page is not protected on port "+port);
}

i = 0;
u[i] = "superman";	p[i++] = "21241036";
u[i] = "super";		p[i++] = "5777364";

for (i = 0; ! isnull(u[i]); i ++)
{
  w = http_send_recv3(method:"GET", item:"/", port: port, username: u[i], password: p[i], exit_on_fail: TRUE);
  if ("200 OK" >< w[0])
  {
    report =
      '\nNessus was able to gain access to the administrative interface using' +
      '\nthe following information :' +
      '\n' +
      '\n  URL      : ' + build_url(qs:"/", port:port) +
      '\n  User     : ' + u[i] +
      '\n  Password : ' + p[i] + '\n';
    security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  }
}
exit(0, "The web server listening on port "+port+" is not affected.");
