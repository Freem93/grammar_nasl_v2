#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42339);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/29 18:09:14 $");

  script_name(english:"Adobe ColdFusion Detection");
  script_summary(english:"Looks for the ColdFusion admin settings page.");

  script_set_attribute(attribute:"synopsis", value:
"A web application platform was detected on the remote web server.");
  script_set_attribute( attribute:"description", value:
"Adobe ColdFusion (formerly Macromedia ColdFusion), a rapid application
development platform, is running on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/coldfusion-family.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = 'ColdFusion';
port = get_http_port(default:80);

# The installer always puts ColdFusion in the same location
dir  = '/CFIDE';
item = '/administrator/settings/version.cfm';
url  = dir + item;
installs = 0;
ver = NULL;

# 8.x, 9.x use an image on login page for version display
login_ver_pats = make_list(
  'Version:[\r\n]+ ([0-9,_hf]+)</strong><br', # 6.x
  'Version:[\r\n]+([0-9,_hf]+)</strong>'      # 7.x
);

sysinfo_ver_pats = make_list(
  'Version[\r\n]+.*&nbsp;</p>[\r\n]+.*</td>[\r\n]+.*class="color-row">[\r\n]+.*&nbsp; ([0-9,_hf]+)', # 6.x
  'Version[\r\n\t]+</td>[\r\n\t]+<td nowrap.*[\r\n\t]+([0-9,_hf]+)' # 7.x, 8.x, 9.x
);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

if ("ColdFusion" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

if ('<title>ColdFusion Administrator Login</title>' >< res[2])
{
  foreach pat (login_ver_pats)
  {
    vmatches = eregmatch(pattern:pat, string:res[2]);
    if (vmatches)
    {
      ver = str_replace(string:vmatches[1], find:",", replace:".");
      break;
    }
  }
}

# No admin password is set
if ('<title>System Information</title>' >< res[2] &&
  (
    'METHOD="POST" onSubmit="return _CF_checkCFForm' >< res[2] ||
    'method="post" onSubmit="return _CF_checkCFForm' >< res[2] ||
    'method="post" onsubmit="return _CF_checkCFForm' >< res[2]
  )
)
{
  set_kb_item(name:"www/"+port+"/coldfusion/no_admin_password", value:TRUE);
  foreach pat (sysinfo_ver_pats)
  {
    vmatches = eregmatch(pattern:pat, string:res[2]);
    if (vmatches)
    {
      ver = str_replace(string:vmatches[1], find:",", replace:".");
      break;
    }
  }
}

# If we failed to detect version 6 or 7, try to detect 8 or 9.
if (empty_or_null(ver))
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/CFIDE/adminapi/base.cfc?wsdl"
  );

  if (!empty_or_null(res))
  {
    vmatches = eregmatch(string:res[2], pattern:"<!--.*ColdFusion version ([0-9,]+)-->");
    if (!empty_or_null(vmatches)) ver = str_replace(string:vmatches[1], find:",", replace:".");
  }
}

# try requesting a different page to get version 10
if (empty_or_null(ver))
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/CFIDE/services/pdf.cfc?wsdl"
  );

  if (!empty_or_null(res))
  {
    vmatches = eregmatch(string:res[2], pattern:"<!--.*ColdFusion version ([0-9,]+)-->");
    if (!empty_or_null(vmatches)) ver = str_replace(string:vmatches[1], find:",", replace:".");
  }
}

# Try at least seeing if we have any info to show it's version 11
if (empty_or_null(ver))
{
   res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/CFIDE/administrator/help/index.html"
  );

  if (!empty_or_null(res))
  {
    vmatches = eregmatch(string:res[2], pattern:"Configuring and Administering ColdFusion ([0-9]+)");
    if (!isnull(vmatches[1])) ver = vmatches[1];
  }
}

if (empty_or_null(ver)) ver = UNKNOWN_VER;

register_install(
  app_name : app,
  path     : dir,
  port     : port,
  version  : ver,
  cpe      : "cpe:/a:adobe:coldfusion",
  webapp   : TRUE
);

# Report findings.
report_installs(port:port);
