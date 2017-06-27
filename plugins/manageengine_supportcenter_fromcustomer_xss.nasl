#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62785);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(56095);
  script_osvdb_id(86597);
  script_xref(name:"EDB-ID", value:"22040");

  script_name(english:"ManageEngine SupportCenter Plus HomePage.do fromCustomer Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine SupportCenter Plus installed on the remote
host is affected by a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input to the 'fromCustomer'
parameter of the 'HomePage.do' script.  An attacker may be able to
leverage this to inject arbitrary HTML and script code into a user's
browser to be executed within the security context of the affected site. 

The application is reportedly also affected by an arbitrary file
upload vulnerability and a persistent cross-site scripting
vulnerability, although Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://supportcenter.wiki.zoho.com/ReadMe-V2.html#7910");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.9.0 Build 7910 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_supportcenter_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/manageengine_supportcenter");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(
  appname:"manageengine_supportcenter",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
xss_test = "';alert('" + SCRIPT_NAME +"-"+ unixtime() + "'); var frompor='null";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/HomePage.do',
  qs       : 'fromCustomer=' + urlencode(str:xss_test),
  pass_str : "var frompor = '" + xss_test,
  pass_re  : 'Copyright &copy; [0-9]+ ZOHO Corporation'
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine SupportCenter Plus",  build_url(qs:dir + "/", port:port));
