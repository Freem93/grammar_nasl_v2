#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63334);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id("CVE-2011-5247", "CVE-2011-5249", "CVE-2011-5250");
  script_bugtraq_id(56883);
  script_osvdb_id(88340, 88341, 88342);

  script_name(english:"Snare Agent for Linux < 1.7.0 / 2.0.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Snare Agent for Linux");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an auditing application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Snare Agent for Linux hosted on the remote web server is affected by
multiple vulnerabilities in the optionally configured web interface:

  - The web interface discloses a hashed password for
    remote logins.  An attacker can view the page source
    at /remote and see the hashed password in the
    'RemotePassword' field. (CVE-2011-5247)

  - The web interface suffers from a cross-site scripting
    vulnerability because the application fails to
    sanitize input passed via logged events.  An attacker
    could create a specially crafted request that would
    execute arbitrary script code in a user's browser.
    (CVE-2011-5249)

  - The web interface suffers from a cross-site request
    forgery (CSRF) vulnerability because it fails to
    properly implement the 'ChToken' parameter used to
    prevent CSRF attacks. (CVE-2011-5250)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/76");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/77");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/78");
  # "http://sourceforge.net/p/snare/news/2011/08/snare-for-linux-170-and-200-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1b3613e");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.7.0 / 2.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intersect_alliance:snare_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("snare_agent_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/snare_linux");
  script_require_ports("Services/www", 80, 6161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:6161, embedded:TRUE);

install = get_install_from_kb(
  appname      : "snare_linux",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir+"/");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Snare Agent for Linux", install_url);

ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

# versions less than 1.7.0 / 2.0.0 are affected
if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 7)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.7.0 / 2.0.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Snare Agent for Linux", install_url, version);
