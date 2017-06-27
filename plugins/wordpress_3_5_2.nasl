#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67021);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/13 21:07:15 $");

 script_cve_id(
    "CVE-2013-2173",
    "CVE-2013-2199",
    "CVE-2013-2200",
    "CVE-2013-2201",
    "CVE-2013-2202",
    "CVE-2013-2203",
    "CVE-2013-2204",
    "CVE-2013-2205"
 );
 script_bugtraq_id(
   60477,
   60757,
   60758,
   60759,
   60770,
   60775,
   60781,
   60825,
   60892
 );
 script_osvdb_id(
   94235,
   94783,
   94784,
   94785,
   94786,
   94787,
   94788,
   94789,
   94790,
   94791
 );

  script_name(english:"WordPress < 3.5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application contains a denial of service attack,
    affecting sites using password-protected posts.
    (CVE-2013-2173)

  - The application is affected by a server-side request
    forgery vulnerability. This vulnerability can be used
    to gain access to a site. (CVE-2013-2199)

  - A privilege escalation vulnerability exists that allows
    contributors to publish posts and users to reassign
    authorship. (CVE-2013-2200)

  - A cross-site scripting vulnerability exists related to
    uploading media. (CVE-2013-2201)

  - A XML External Entity Injection (XXE) vulnerability
    exists in 'oEmbed'. (CVE-2013-2202)

  - A vulnerability exists disclosing a full file path
    related to file upload. (CVE-2013-2203)

  - A cross-site scripting vulnerability exists related
    to 'TinyMCE' library. (CVE-2013-2204)

  - The application is affected by a cross-site scripting
    vulnerability in the 'SWFUpload' library.
    (CVE-2013-2205)

  - Cross-site scripting vulnerabilities exist in the
    'post.php' script relating to the 'excerpt' and
    'content' parameters.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2013/06/wordpress-3-5-2/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.5.2");
  # http://core.trac.wordpress.org/log/branches/3.5?rev=24498&stop_rev=23347
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb617238");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jul/7");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 3.5.2 are vulnerable
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 5) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 2)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.5.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
