#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65948);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/25 19:41:15 $");

  script_cve_id("CVE-2013-2503");
  script_bugtraq_id(58425);
  script_osvdb_id(91126);

  script_name(english:"Privoxy < 3.0.21 Multiple Information Disclosure Vulnerabilities");
  script_summary(english:"Checks the version of Privoxy.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web proxy is affected by multiple information disclosure
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the Privoxy installed
on the remote host is a version prior to 3.0.21. It is, therefore,
affected by multiple information disclosure vulnerabilities due to the
application not properly handling Proxy-Authenticate and
Proxy-Authorization headers. This can allow a remote, malicious HTTP
server to spoof the intended proxy service via a 407 (Proxy
Authentication Required) HTTP status code and thereby gain access to
user credentials.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/62");
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/ChangeLog?revision=1.190&view=markup
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3511a155");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:privoxy:privoxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("privoxy_detect.nasl");
  script_require_keys("www/Privoxy", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8118);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8118);
app_name = "Privoxy";

install = get_install_from_kb(
  appname      : app_name,
  port         : port,
  exit_on_fail : TRUE
);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

install_url = build_url(qs:install["dir"], port:port);
fix = "3.0.21";

# Versions < 3.0.21 are vulnerable
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
