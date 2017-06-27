#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62385);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_bugtraq_id(55619);
  script_osvdb_id(90058);

  script_name(english:"Poweradmin index.php XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Poweradmin install hosted on the remote web server is affected by a
cross-site scripting vulnerability because it fails to properly sanitize
user input appended to the URL of the 'index.php' script.  An attacker
may be able to leverage this to inject arbitrary HTML and script code
into a user's browser to be executed within the security context of the
affected site.");
  # http://packetstormsecurity.org/files/116698/Poweradmin-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adbe2301");
  # https://github.com/poweradmin/poweradmin/commit/f5edf5d98b630149e43fa356e474f33e9504df91
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe4b4f6e");
  # https://www.poweradmin.org/trac/wiki/News/CallfortestingPoweradmin2.1.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?559bd5a7");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:poweradmin:poweradmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

if (thorough_tests)
  dirs = list_uniq(make_list("/poweradmin", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

xss_test = '"><script>alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ');</script>';

pass_re = str_replace(string:xss_test, find:"(", replace:"\(");
pass_re = str_replace(string:pass_re, find:")", replace:"\)");


# Check for Poweradmin
exploited = 0;
install_urls = make_list();

foreach dir (dirs)
{
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/index.php",
    port         : port,
    exit_on_fail : TRUE
  );
  if (
    (
      'href="https://www.poweradmin.org/">a complete(r) <strong>poweradmin</strong>' >< res[2] ||
      '<a href="http://poweradmin.org"' >< res[2] ||
      '<a href=https://rejo.zenger.nl/poweradmin/' >< res[2]
    ) &&
    (
      '<h2>Login</h2>' >< res[2] ||
      '<h2>Log in</h2>' >< res[2]
    )
  )
  {
    install_urls = make_list(install_urls, build_url(qs:dir+"/index.php", port:port));

    if (test_cgi_xss(
      port     : port,
      dirs     : make_list(dir),
      cgi      : '/index.php/' + xss_test,
      pass_re  : '<form method="post" action="(.+)/index.php/' + pass_re,
      ctrl_re  : '<h2>Login</h2>',
      no_qm    : TRUE
    )) exploited++;
  }
}


if (exploited) exit(0);
else
{
  installs = max_index(install_urls);
  if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, "Poweradmin", port);
  else if (installs == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, "Poweradmin", install_urls[0]);
  else exit(0, "None of the Poweradmin installs (" + join(install_urls, sep:" & ") + ") are affected.");
}
