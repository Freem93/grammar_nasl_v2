#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64377);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2013-0229", "CVE-2013-0230");
  script_bugtraq_id(57607, 57608);
  script_osvdb_id(89624, 89625);
  script_xref(name:"EDB-ID", value:"25975");
  script_xref(name:"EDB-ID", value:"36839");
  script_xref(name:"EDB-ID", value:"37517");

  script_name(english:"MiniUPnP < 1.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the miniupnp version.");

  script_set_attribute(attribute:"synopsis", value:
"A network service running on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of MiniUPnP running on the remote
host is prior to 1.4. It is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read error exists in the
    ProcessSSDPRequest() function in file minissdp.c that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition via a specially crafted
    M-SEARCH request. (CVE-2013-0229)

  - A stack-based buffer overflow condition exists in the
    ExecuteSoapAction() function in the SOAPAction handler,
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    long quoted method, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2013-0230)");
  # https://community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37da582a");
  script_set_attribute(attribute:"see_also", value:"https://community.rapid7.com/docs/DOC-2150");
  # https://community.rapid7.com/servlet/JiveServlet/download/2150-1-16596/SecurityFlawsUPnP.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54e32505");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MiniUPnP version 1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MiniUPnPd 1.0 Stack Buffer Overflow Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30"); # miniupnpd 1.4 released
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:miniupnp_project:miniupnpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("upnp_search.nasl", "http_version.nasl");
  script_require_ports("upnp/server", "Services/www");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

global_var fix, vuln;
fix = '1.4';
vuln = FALSE;

##
# Checks if the given server banner is from a vulnerable
# version of miniupnpd.  If so, a reporting function is
# called
#
# @param port port number of the service being tested
# @param server server banner advertised on "port"
# @param proto the protocol the port is accessible by (tcp or udp)
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
      '\n  Server banner : ' + banner +
      '\n  Installed version : ' + ver[1] +
      '\n  Fixed version : ' + fix + '\n';

    security_report_v4(port:port,
                       proto:proto,
                       severity:SECURITY_HOLE,
                       extra:report);
  }
}

# check the server string retrieved via UDP 1900 by upnp_search.nasl
servers = get_kb_list('upnp/server');
foreach(server in servers) _check_miniupnp_version(port:1900, server:server, proto:'udp');

# check any server strings retrieved via HTTP
www_ports = get_kb_list('Services/www');

foreach port (www_ports)
{
  server = http_server_header(port:port);
  if (isnull(server)) continue;

  _check_miniupnp_version(port:port, server:server, proto:'tcp');
}

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');
