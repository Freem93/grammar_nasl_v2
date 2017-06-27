#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53449);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/04 15:52:09 $");

  script_cve_id("CVE-2011-1587");
  script_bugtraq_id(47354);
  script_osvdb_id(74619);
  script_xref(name:"Secunia", value:"44142");

  script_name(english:"MediaWiki API XSS");
  script_summary(english:"Checks for cross-site scripting in API queries.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a version of MediaWiki that is affected by
a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A cross-site scripting vulnerability exists in this installation of
MediaWiki that allows an attacker to execute arbitrary script code in
the browser of an unsuspecting user. Such script code could steal
authentication credentials and be used to launch other attacks."
  );
   # http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-April/000097.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb194760");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=28507"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.16.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

# Create a query to trigger the vulnerability.
xss = "action=query&meta=siteinfo&format=json&siprop=<body+onload=alert('XSS')>.html?";
exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : "/api%2Ephp",
  qs       : xss,
  pass_str : "<body onload=alert('XSS')>",
  ctrl_re  : '{"warnings":'
);
if (!exploit)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
