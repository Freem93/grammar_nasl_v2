#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81086);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/25 19:41:15 $");

  script_cve_id("CVE-2015-1030", "CVE-2015-1031");
  script_bugtraq_id(71991, 71993);
  script_osvdb_id(116842, 116843);

  script_name(english:"Privoxy < 3.0.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Privoxy.");

  script_set_attribute(attribute:"synopsis", value:"The remote web proxy is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the Privoxy installed
on the remote host is a version prior to 3.0.22. It is, therefore,
affected by multiple vulnerabilities:

  - An denial of service vulnerability exists due to a
    memory leak when client connections are rejected when
    the socket limit has been reached. Note that this issue
    only affects version 3.0.21 with IPv6 support, which is
    enabled by default. (CVE-2015-1030)

  - Multiple unspecified use-after-free vulnerabilities
    exist that could lead to arbitrary code execution.
    (CVE-2015-1031)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/p/ijbswa/mailman/message/33089172/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:privoxy:privoxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
fix = "3.0.22";

# Versions < 3.0.22 are vulnerable
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
