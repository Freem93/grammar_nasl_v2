#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69280);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2013-5583");
  script_bugtraq_id(61600);
  script_osvdb_id(95998);

  script_name(english:"Joomla! 'lang' Parameter XSS");
  script_summary(english:"Attempts to inject script code via the lang parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is affected by a
cross-site scripting (XSS) vulnerability in idna_convert/example.php
due to improper sanitization of user-supplied input to the 'lang'
parameter before using it to generate dynamic HTML content. An
unauthenticated, remote attacker can exploit this to inject arbitrary
HTML and script code into the user's browser session.");
  # https://web.archive.org/web/20160402054936/http://disse.cting.org/2013/08/05/joomla-core-3_1_5_reflected-xss-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ceaad26b");
  script_set_attribute(attribute:"see_also", value:"https://github.com/joomla/joomla-cms/issues/1658");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time. It is suggested that the script be removed.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
xss_test = '";><script>alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ');</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/libraries/idna_convert/example.php',
  qs       : 'lang=' + xss_test,
  pass_str : 'name="lang" value="' + xss_test,
  pass_re  : 'name="idn_version"'
);

if (!exploit)
{
  install_url = build_url(qs: dir, port: port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
