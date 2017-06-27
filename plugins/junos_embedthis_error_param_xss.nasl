#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70922);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(63656);
  script_osvdb_id(99758);

  script_name(english:"Juniper Junos EmbedThis AppWeb error Parameter XSS");
  script_summary(english:"Tries to inject script code through 'error' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Junos installed on the remote host is affected by a
cross-site scripting vulnerability because it fails to properly sanitize
user-supplied input to the 'error' parameter of the 'index.php' script. 

An attacker may be able to leverage this issue to inject arbitrary HTML
and script code into a user's browser to be executed within the security
context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/529750");
  script_set_attribute(attribute:"solution", value:"There is no solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "appweb_server_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:TRUE);

# Make sure the server is running Appweb.
get_kb_item_or_exit('www/'+port+'/appweb');

dir = "/";
page = "index.php";
url = dir + page;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
if ('<title>Log In - Juniper Web Device Manager</title>' >!< res[2]) audit(AUDIT_WEB_APP_NOT_INST, 'Juniper Web Device Manager (J-Web)', port);

alert = string("<script>alert('", SCRIPT_NAME, "')</script>&uname=bGF");
vuln = test_cgi_xss(
  port     : port,
  cgi      : page,
  dirs     : make_list(dir),
  qs       : "name=Test&error="+urlencode(str:alert),
  pass_str : '<div id="errorMsgId">'+alert,
  pass2_re : "title>Log In - Juniper Web Device Manager"
);

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "AppWeb on Junos", build_url(qs:dir+page,port:port));
