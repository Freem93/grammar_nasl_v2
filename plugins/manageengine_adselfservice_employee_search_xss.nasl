#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57049);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2010-3274", "CVE-2011-5105");
  script_bugtraq_id(46331, 50717);
  script_osvdb_id(70872);

  script_name(english:"ManageEngine ADSelfService EmployeeSearch.cc Multiple XSS");
  script_summary(english:"Tries to exploit a cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The instance of ManageEngine ADSelfService Plus running on the remote
web server is affected by multiple cross-site scripting
vulnerabilities in the EmployeeSearch.cc script due to improper
sanitization of user-supplied input to the 'searchString',
'searchType' and 'actionID' parameters. An unauthenticated, remote
attacker can exploit these vulnerabilities, via a specially crafted
URL, to execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"solution", value:
"There is currently no patch available from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://jameswebb.me/vulns/vrpth-2011-001.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

port    = get_http_port(default:8888);

install = get_single_install(
  app_name : 'ManageEngine ADSelfService Plus',
  port    : port
);

dir = install['path'];
cgi = 'EmployeeSearch.cc';
qs  = 'searchType=contains&searchBy=ALL_FIELDS&searchString=';

xss = '";alert("'+SCRIPT_NAME+'-'+unixtime()+'");//\\"';
expected_output = 'var searchValue = "' + xss;

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : cgi,
  qs       : qs+xss,
  pass_str : expected_output,
  ctrl_re  : 'title>.*ManageEngine - ADSelfService',
  pass_re  : 'src="js/Esearch.js"'
);

if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine ADSelfService Plus", build_url(qs:dir+cgi, port:port));
