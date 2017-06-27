#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62368);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2012-2698");
  script_bugtraq_id(53998);
  script_osvdb_id(82983);

  script_name(english:"MediaWiki index.php 'uselang' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MediaWiki running on the remote host is affected by a
cross-site scripting vulnerability due to a failure to properly
sanitize user-supplied input to the 'uselang' parameter in the
'index.php' script. An attacker can exploit this to inject arbitrary
HTML and script code into a user's browser to be executed within the
security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=36938");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-June/000116.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e95f992");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-June/000117.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf5ace4f");
  #http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-June/000118.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42466623");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.17.5 / 1.18.4 / 1.19.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
xss_test = "a' onmouseover=eval(alert('" + SCRIPT_NAME + "-" + unixtime() + "')) e='";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/index.php',
  qs       : 'uselang=' + urlencode(str:xss_test),
  pass_str : "lang='" + xss_test + "' dir='",
  pass_re  : 'mediawiki'
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
