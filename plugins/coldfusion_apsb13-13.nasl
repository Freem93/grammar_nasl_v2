#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66407);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/29 18:09:14 $");

  script_cve_id("CVE-2013-1389");
  script_bugtraq_id(59849);
  script_osvdb_id(93321);
  script_xref(name:"TRA", value:"TRA-2013-04");
  script_xref(name:"CERT", value:"113732");

  script_name(english:"Adobe ColdFusion Authentication Bypass (APSB13-13)");
  script_summary(english:"Bypasses authentication and causes an error message.");

  script_set_attribute(attribute:"synopsis", value:
"A web management interface on the remote host has an authentication
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host has an
authentication bypass vulnerability. When RDS is disabled and not
configured with password protection, it is possible to authenticate as
an administrative user without providing a username or password. A
remote, unauthenticated attacker can exploit this to gain
administrative access to the ColdFusion Administrator interface. After
authenticating, it is possible to write arbitrary files to the host,
resulting in arbitrary code execution. 

All versions of ColdFusion 10 are affected. ColdFusion 9, 9.0.1, and
9.0.2 are only affected when the hotfixes for APSB13-03 have been
applied and web.xml is configured to allow access to the RDS servlet.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-04");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-13.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b1d947");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix referenced in Adobe security bulletin
APSB13-13.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

# The vulnerability's present if RDS is disabled _and_ configured to not require
# authentication. In the name of avoiding false positives and negatives,
# this plugin will only bail out if RDS is enabled and authentication
# is not required, an issue which is already reported by a different
# plugin (coldfusion_rds_unauthenticated.nasl)
rds_enabled = get_kb_item('coldfusion/' + port + '/rds/enabled');
if (rds_enabled)
  exit(0, "RDS is enabled on the " +app+ " install at " + install_url);

# try to read a file that is unlikely to exist. if the server gives an indication
# that it attempted to and failed to read the file (which should require authentication),
# that means the system is vulnerable. we need to do this because it results in an unhandled
# exception which is displayed in the server's response. we can't read a file that exists
# because even though the server will read the file, it will return an error message that
# says something like "access denied" instead of the file's contents
file = 'nonexistent-' + unixtime();
cmd = 'READ';
req =
  '2:' +
  'STR:' + strlen(file) + ':' + file +
  'STR:' + strlen(cmd) + ':' + cmd;
url = '/CFIDE/main/ide.cfm?ACTION=fileio';
res = http_send_recv3(method:'POST', item:url, port:port, data:req, exit_on_fail:TRUE);

# java.io.FileNotFoundException: nonexistent-1360956655 (No such file or directory)
# java.io.FileNotFoundException: nonexistent-1360956655 (The system cannot find the file specified)
if ('java.io.FileNotFoundException: ' + file >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

if (report_verbosity > 0)
{
  report =
    '\nNessus determined the host is vulnerable by sending the following request' +
    '\nto read a file without authentication :\n\n' +
    crap(data:"-" , length:29) +  " start of request " + crap(data:"-", length:28) + '\n' +
    http_last_sent_request() + '\n' +
    crap(data:"-" , length:29) +  " end of request " + crap(data:"-", length:30) + '\n' +
    '\nThe server responded with the following error message, indicating that it' +
    '\nprocessed the file read request without requiring authentication :\n\n' +
    crap(data:"-" , length:29) +  " server response " + crap(data:"-", length:29) + '\n';

  # showing the whole stack trace is overkill, only the first few lines that show
  # the file read failed should be good enough
  lines = split(res[2], sep:'\n', keep:TRUE);
  for (i = 0; i < 5 && i < max_index(lines); i++)
    report += lines[i];

  report += crap(data:"-" , length:29) +  " server response " + crap(data:"-", length:29) + '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);
