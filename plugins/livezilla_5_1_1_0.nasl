#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71441);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2013-6223",
    "CVE-2013-6224",
    "CVE-2013-6225",
    "CVE-2013-7002"
  );
  script_bugtraq_id(63764, 63998, 64001, 64174, 64176);
  script_osvdb_id(99991, 100399, 100400, 100401, 100402, 100741);
  script_xref(name:"EDB-ID", value:"29672");

  script_name(english:"LiveZilla < 5.1.1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of LiveZilla.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LiveZilla hosted on the remote web server is affected
by multiple vulnerabilities :

  - The application saves admin login details in a 1 click
    XML file. This allows a local attacker to obtain admin
    login credentials. (CVE-2013-6223)

  - The application is affected by multiple cross-site
    scripting vulnerabilities because it fails to
    properly sanitize user-supplied input.
    (CVE-2013-6224, CVE-2013-7002)

  - The application is affected by a local file inclusion
    vulnerability that can be exploited to view arbitrary
    files or execute arbitrary PHP code on the remote host.
    (CVE-2013-6225)");
  script_set_attribute(attribute:"see_also", value:"http://www.curesec.com/data/advisories/Curesec-2013-1006.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.curesec.com/data/advisories/Curesec-2013-1007.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.curesec.com/data/advisories/Curesec-2013-1008.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.livezilla.net/board/index.php?/topic/163-livezilla-changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to LiveZilla version 5.1.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:livezilla:livezilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("livezilla_detect.nbin");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/LiveZilla", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

appname = "LiveZilla";

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
path    = install["path"];
version = install["version"];
install_url = build_url(port:port, qs:path);

fix = '5.1.1.0';

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 5 ||
  (ver[0] == 5 && ver[1] < 1) ||
  (ver[0] == 5 && ver[1] == 1 && ver[2] < 1)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
