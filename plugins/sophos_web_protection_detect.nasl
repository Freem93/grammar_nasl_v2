#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65873);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/06 17:22:31 $");

  script_name(english:"Sophos Web Protection Detection");
  script_summary(english:"Checks for Sophos Web Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A web security application is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Sophos Web Protection, a web security application, is running on the
remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.sophos.com/en-us/products/secure-web-gateway.aspx");
  script_set_attribute(attribute:"see_also", value:"https://community.sophos.com/kb/en-us/123446");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sophos:sophos_web_protection");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Sophos Web Protection';
port = get_http_port(default:443);

###
# Collects information from the /help/about.php page
#
# @return an array of values taken from the about page
###
function do_about_page()
{
  local_var result = make_array();
  local_var resp = http_send_recv3(
    port:port,
    method:'GET',
    item:'/help/about.php',
    exit_on_fail:FALSE);
  if (isnull(resp) || "200" >!< resp[0]) return result;

  local_var pattern = 'Serial number</div></td>[ \r\n\t]+<td width=\"[0-9]+\"><div align=\"left\">([0-9A-Za-z_]+)';
  local_var match = eregmatch(pattern:pattern, string:resp[2]);
  if (!isnull(match)) result['Serial Number'] = match[1];

  pattern = 'Number of users </div></td>[ \r\n\t]+<td><div align=\"left\">([0-9]+)';
  match = eregmatch(pattern:pattern, string:resp[2]);
  if (!isnull(match)) result['Number of Users'] = match[1];

  pattern = 'License Type</div></td>[ \r\n\t]+<td><div align=\"left\">([a-zA-Z]+)';
  match = eregmatch(pattern:pattern, string:resp[2]);
  if (!isnull(match)) result['License Type'] = match[1];

  pattern = 'License term</div></td>[ \r\n\t]+<td><div align=\"left\">([-.0-9 a-zA-Z]+)';
  match = eregmatch(pattern:pattern, string:resp[2]);
  if (!isnull(match)) result['License Term'] = match[1];

  return result;
}

path = '/';
res = http_send_recv3(port:port, method:'GET', item:path, exit_on_fail:TRUE);
if ('<title>Sophos Web Appliance</title>' >!< res[2] ||
  '<p>Username</p>' >!< res[2] ||
  '<p>Password</p>' >!< res[2]) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Get WSA_BUILD number
pat = "<script[^<]*src[ \t]*=[ \t]*[\x27\x22][ \t]*/([0-9]+)/[^<]+mm_rollover\.js[^<]*</script>";
matches = pregmatch(string: res[2], pattern: pat);
if(matches) build = matches[1];

extra = do_about_page();

if(build) extra['WSA_BUILD'] = build;

register_install(
  app_name:'sophos_web_protection',
  port:port,
  path:path,
  extra:extra,
  cpe:"x-cpe:/a:sophos:sophos_web_protection");

report_installs();
exit(0);
