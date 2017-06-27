#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26010);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/05/24 02:15:09 $");

 script_cve_id("CVE-2007-4542", "CVE-2007-4629");
 script_bugtraq_id(25582);
 script_osvdb_id(39378, 39379, 41031);

 script_name(english:"MapServer Multiple Remote Vulnerabilities");
 script_summary(english:"Checks for multiple vulnerabilities in MapServer < 4.10.3");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are prone to arbitrary
remote command execution and cross-site scripting attacks.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MapServer, an open source internet map
server.

The installed version of MapServer is affected by multiple cross-site
scripting vulnerabilities and to a buffer overflow vulnerability.  To
exploit those flaws an attacker needs to send specially crafted
requests to the mapserv CGI.

By exploiting the buffer overflow vulnerability, an attacker would be
able to execute code on the remote host with the privileges of the web
server.");
 script_set_attribute(attribute:"solution", value:"Upgrade to MapServer 4.10.3.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/10");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

 script_dependencies("mapserver_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/mapserver", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "MapServer";
port = get_http_port(default:80);
install = get_install_from_kb(appname:'mapserver', port:port, exit_on_fail:TRUE);
version = install['ver'];
url = build_url(port:port, qs:install['dir']);

# Determine fixed version from branch.
if (version =~ "^[0-4]($|[-\.])") fix = "4.10.3";
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(app:'asterisk', ver:version, fix:fix) == -1 )
{
  if(report_verbosity > 0)
  {
    report =
      '\n  URL           : ' + url +
      '\n  Version       : ' + version +
      '\n  Fixed version : ' + fix +
      '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
