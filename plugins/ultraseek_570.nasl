#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23651);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/01/15 12:20:32 $");

  script_cve_id("CVE-2006-5819");
  script_bugtraq_id(21120);
  script_osvdb_id(30286, 30287, 30288);

  script_name(english:"Verity Ultraseek < 5.7 Multiple Vulnerabilities");
  script_summary(english:"Checks for Ultraseek < 5.7");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ultraseek, an enterprise web search engine. 

According to the version in its banner, an unauthenticated, remote
attacker reportedly can use '/highlight/index.html' script on the remote
install of Ultraseek as a proxy to launch web attacks or even enumerate
internal addresses and ports. 

In addition, the remote software also suffers from numerous information
disclosure vulnerabilities through other scripts.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-042.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/451847/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.ultraseek.com/support/docs/RELNOTES.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Ultraseek 5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:autonomy_ultraseek");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8765);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8765);

app_name = 'HP Autonomy Ultraseek';

server_header = http_server_header(port:port);
if (isnull(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ('ultraseek' >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, app_name);

match = eregmatch(string:server_header, pattern:'[Uu]ltraseek[/|\\s]((?:\\d+\\.)*\\d+)');
if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
version_discovered = match[1];

version_fixed = '5.7';
if (ver_compare(ver:version_discovered, fix:version_fixed, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version_discovered +
      '\n  Fixed version     : ' + version_fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version_discovered);
