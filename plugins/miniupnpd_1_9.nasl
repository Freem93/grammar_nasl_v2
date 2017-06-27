#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80889);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_bugtraq_id(71624);
  script_osvdb_id(
    115649,
    115652,
    115653,
    115661
  );

  script_name(english:"MiniUPnP < 1.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the miniupnp version.");

  script_set_attribute(attribute:"synopsis", value:
"A network service running on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of MiniUPnP running on the remote
host is prior to 1.9. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw exists in the Domain Name System
    (DNS) related to the 'rebinding' interaction. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted web page,
    to run a client-side script that interacts with the
    systems on their network. (VulnDB 115649)

  - A flaw exists in the GetListOfPortMappings() function
    within file upnpsoap.c due to improper sanitization of
    user-supplied input when handling SOAP connections. An
    unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (VulnDB 115652)

  - A buffer overflow condition exists in the
    ParseHttpHeaders() function within file upnphttp.c due
    to improper validation of user-supplied input when
    handling Content-Length HTTP headers. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to cause a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 115653)

  - A flaw exists in the BuildHeader_upnphttp() function
    within file upnphttp.c due to insufficient checking for
    memory allocation failures. An unauthenticated, remote
    attacker can exploit this to have an unspecified impact.
    (VulnDB 115661)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://miniupnp.free.fr/files/changelog.php?file=miniupnpd-1.9.20141209.tar.gz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7516605f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MiniUPnP version 1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:miniupnp_project:miniupnpd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("upnp_search.nasl", "http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("upnp/server", "Services/www");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

global_var fix, vuln;
fix = '1.9';
vuln = FALSE;

##
# Checks if the given server banner is from a vulnerable
# version of miniupnpd.  If so, a reporting function is
# called
#
# @param port port number of the service being tested
# @param server server banner advertised on "port"
# @param proto the protocol the port is accessible by (tcp or udp)
# @param if TRUE, specifies that "port" is a UDP port
##
function _check_miniupnp_version(port, server, proto)
{
  local_var ver, report, banner;
  server = chomp(server);
  ver = eregmatch(string:server, pattern:'miniupnpd/([0-9.]+)', icase:TRUE);

  if (!isnull(ver) && ver_compare(ver:ver[1], fix:fix, strict:FALSE) < 0)
  {
    vuln = TRUE;
    banner = ereg_replace(string:server, pattern:'SERVER: *(.+)', replace:"\1", icase:TRUE);
    report =
      '\n  Server banner     : ' + banner +
      '\n  Installed version : ' + ver[1] +
      '\n  Fixed version     : ' + fix + '\n';

    security_report_v4(port:port,
                       proto:proto,
                       severity:SECURITY_HOLE,
                       extra:report);
  }
}

# check the server strings retrieved via UDP 1900 by upnp_search.nasl
servers = get_kb_list('upnp/server');
foreach (server in servers) _check_miniupnp_version(port:1900, server:server, proto:'udp');

# check any server strings retrieved via HTTP
www_ports = get_kb_list('Services/www');
foreach port (www_ports)
{
  server = http_server_header(port:port);
  if (isnull(server)) continue;

  _check_miniupnp_version(port:port, server:server, proto:'tcp');
}

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');
