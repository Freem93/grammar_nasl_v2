#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54970);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/05 04:45:41 $");

  script_cve_id("CVE-2011-1026", "CVE-2011-1077");
  script_bugtraq_id(48011, 48015);
  script_osvdb_id(
    73153,
    73154,
    94610,
    94611,
    94612,
    94613,
    94614,
    94615,
    94616,
    94617,
    94618
  );

  script_name(english:"Apache Archiva < 1.3.5 Multiple Vulnerabilities");
  script_summary(english:"Checks Archiva version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the instance of Apache
Archiva hosted on the remote web server is earlier than 1.3.5 and thus
is affected by multiple persistent and reflective cross-site scripting
and cross-site request forgery vulnerabilities.

If an attacker can trick a user of the affected application into
following a malicious link, this issue could be leveraged to inject
arbitrary HTML or script code into the user's browser to be executed
within the security context of the affected site."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/518188/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/518189/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archiva.apache.org/security.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apache Archiva 1.3.5 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/05");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:archiva");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("archiva_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/archiva");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080, embedded:FALSE);

install = get_install_from_kb(appname:'archiva', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir+'/index.action');

version = install['ver'];
if (version == UNKNOWN_VER) 
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Apache Archiva", install_url);

if (
  version =~ '^1\\.[0-2]($|[^0-9])' ||
  version =~ '^1\\.3($|[^0-9.])' ||
  version =~ '^1\\.3\\.[1-4]($|[^0-9])'
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.5' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Apache Archiva", install_url, version);
