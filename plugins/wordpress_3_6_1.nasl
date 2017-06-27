#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69997);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 15:05:43 $");

  script_cve_id(
    "CVE-2013-4338",
    "CVE-2013-4339",
    "CVE-2013-4340",
    "CVE-2013-5738",
    "CVE-2013-5739"
  );
  script_bugtraq_id(
    62344,
    62345,
    62346,
    62421,
    62424,
    64453,
    64456
  );
  script_osvdb_id(
    97210,
    97211,
    97212,
    97213,
    97214,
    101181,
    101182
  );

  script_name(english:"WordPress < 3.6.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress install hosted on the
remote web server is affected by multiple vulnerabilities :

  - Unsafe PHP de-serialization could occur in limited
    situations and setups, which could lead to remote code
    execution. (CVE-2013-4338)

  - Open redirect/insufficient input validation could allow
    attackers to redirect users to a malicious website.
    (CVE-2013-4339)

  - A user with an Author role, using a specially crafted
    request, can forge a post that appears to be posted by
    another user. (CVE-2013-4340)

  - As a proactive measure to prevent cross-site scripting
    attacks, extensions .swf, .exe, .htm, and .html are
    filtered from file uploading. (CVE-2013-5738,
    CVE-2013-5739)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2013/09/wordpress-3-6-1/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.6.1");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Dec/174");
  # http://core.trac.wordpress.org/log/branches/3.6?stop_rev=24972&rev=25345
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c1affab");
  script_set_attribute(attribute:"see_also", value:"http://core.trac.wordpress.org/changeset/25321");
  script_set_attribute(attribute:"see_also", value:"http://core.trac.wordpress.org/changeset/25322");
  script_set_attribute(attribute:"see_also", value:"http://core.trac.wordpress.org/changeset/25323");
  script_set_attribute(attribute:"see_also", value:"http://core.trac.wordpress.org/changeset/25324");
  script_set_attribute(attribute:"see_also", value:"http://core.trac.wordpress.org/changeset/25325");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

# Versions less than 3.6.1 are vulnerable
if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 1)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.6.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
