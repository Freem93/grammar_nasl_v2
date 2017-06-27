#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52455);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2011-1007", "CVE-2011-1008");
  script_bugtraq_id(46493);
  script_osvdb_id(71011, 71012);
  script_xref(name:"Secunia", value:"43438");

  script_name(english:"Request Tracker 3.x < 3.8.9 Security Bypass and Information Disclosure");
  script_summary(english:"Checks the version of Request Tracker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by security bypass and information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Best Practical
Solutions Request Tracker (RT) running on the remote web server is a
version prior to 3.8.9. It is, therefore, potentially affected by the
following vulnerabilities :

  - If an individual with a valid account logs out of
    Request Tracker but does not close the browser, an
    attacker with access to that browser can use the 'back'
    button to access the previous user's account page.
    (CVE-2011-1007)

  - An information disclosure vulnerability affects the
    application when handling the logging of SQL queries
    during user transition. (CVE-2011-1008)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://lists.bestpractical.com/pipermail/rt-announce/2011-February/000186.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1d8bf43");
  # https://github.com/bestpractical/rt/commit/917c211820590950f7eb0521f7f43b31aeed44c4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f132438");
  # https://github.com/bestpractical/rt/commit/2338cd19ed7a7f4c1e94f639ab2789d6586d01f3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bb973f9");

  script_set_attribute(attribute:"solution", value:"Upgrade to Request Tracker 3.8.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/RT", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "RT";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

path = install['path'];
install_url = build_url(port:port, qs:path + "/");
version = install['version'];

# Versions 3.0.0 - 3.8.9rc1 are affected.
if (version =~ "^3\.([0-7]($|[^0-9])|8\.([0-8]($|[^0-9]+[0-9]+)|9rc1))")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.8.9\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
