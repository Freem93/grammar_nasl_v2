#
# This script was rewritten by Tenable Network Security
#

include("compat.inc");

if (description)
{
 script_id(12295);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/07/29 18:27:55 $"); 

 script_name(english:"Dell OpenManage Server Administrator Detection");
 script_summary(english:"Dell OpenManage Server Administrator Detection.");

 script_set_attribute(attribute:"synopsis", value:
"A management server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"Dell OpenManage Server Administrator (OMSA), a systems management
server, is running on the remote host.");
 # http://en.community.dell.com/techcenter/systems-management/w/wiki/4871.quick-tour-server-administrator
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aa75b74");
 # http://en.community.dell.com/techcenter/systems-management/w/wiki/1760.openmanage-server-administrator-omsa
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aa75b74");
 # http://www.dell.com/support/contents/us/en/04/article/Product-Support/Self-support-Knowledgebase/enterprise-resource-center/SystemsManagement/OMSA
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?039974aa");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:openmanage");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:openmanage_server_administrator");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This is script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/www", 1311);
 script_dependencies("http_version.nasl");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:1311);
# The previous version forced the use of a SSLv23 connection...

params = make_nested_list(
  make_array(
    'url', '/servlet/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin',
    'pattern_list',
      make_list(
        '<br>Version ([0-9.]+)<br>',  # older versions, at least 4.5.0 - 6.3.0 inclusive
        'Dell OpenManage Server Administrator<[^V]+Version ([0-9.]+)<' # older versions, 6.4.0 and later
      )
  ),
  make_array(
    'url', '/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin',
    'pattern_list', make_list('<td.*<span.*Systems Management Software.*Version ([0-9.]+)<') # works on 8.2.0
  )
);

version = NULL;
ver_found = FALSE;

# each url can have multiple patterns to try and match
# loop urls
foreach p (params)
{
  r = http_send_recv3(port:port, method: "GET", item:p['url']);

  foreach pattern (p['pattern_list'])
  {
    match = eregmatch(string:r[2], pattern:pattern);
    if (!isnull(match))
    {
      version = match[1];
      ver_found = TRUE;
      break;
    }
  }
  if (ver_found) break;
}

if (empty_or_null(version)) audit(AUDIT_WEB_FILES_NOT, 'Dell OpenManage Server Administrator', port);

install = add_install(appname:'dell_omsa', port:port, dir:'', ver:version);
report = get_install_report(display_name:'Dell OpenManage Server Administrator', installs:install, port:port);
security_note (port:port, extra:report);

set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
