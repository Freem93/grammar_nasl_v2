#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74189);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id("CVE-2014-1456", "CVE-2014-1457");
  script_bugtraq_id(65571, 65573);
  script_osvdb_id(103318, 103319, 103341);

  script_name(english:"Open Web Analytics < 1.5.6  Multiple Vulnerabilities");
  script_summary(english:"Checks Open Web Analytics version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Open Web Analytics installed
on the remote host is prior to version 1.5.6. It is, therefore,
affected by the following vulnerabilities :

  - A cross-site scripting flaw exists with the login page
    where input to the 'owa_user_id' parameter is not
    properly sanitized. This could allow a remote attacker,
    with a specially crafted request, to execute arbitrary
    code within the browser / server trust relationship.
    (CVE-2014-1456)

  - Multiple cross-site scripting flaws exist with the
    General Configuration Options page where multiple
    parameters are not properly sanitized. This
    could allow a remote attacker, with a specially crafted
    request, to execute arbitrary code within the browser /
    server trust relationship. (VulnDB: 103341)

  - A cross-site request forgery exists with the cross-site
    request forgery prevention scheme where the nonce values
    are not random enough. This could allow a
    context-dependent attacker, with a specially crafted
    link, to trick a user into giving the attacker access to
    sensitive actions. (CVE-2014-1457)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.secureworks.com/advisories/SWRX-2014-004/SWRX-2014-004.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.secureworks.com/advisories/SWRX-2014-005/SWRX-2014-005.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.secureworks.com/advisories/SWRX-2014-006/SWRX-2014-006.pdf");
  # http://www.secureworks.com/resources/videos/dell-secureworks-security-advisory-swrx-2014-006-poc-demo/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fbbd43d");
  script_set_attribute(attribute:"see_also", value:"http://www.openwebanalytics.com/?p=384");
  script_set_attribute(attribute:"solution", value:"Upgrade to Open Web Analytics 1.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openwebanalytics:open_web_analytics");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("open_web_analytics_detect.nbin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/openwebanalytics", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : 'openwebanalytics',
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];

install_loc = build_url(port:port, qs:dir + "/");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Open Web Analytics", install_loc);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions < 1.5.6 are vulnerable
fixed = '1.5.6';

suffixes = make_array(-1,"rc(\d+)");

if (ver_compare(ver:version, fix:fixed, regexes:suffixes) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' + fixed + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Open Web Analytics", install_loc, version);
