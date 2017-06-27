#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64394);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id(
    "CVE-2012-5958",
    "CVE-2012-5959",
    "CVE-2012-5960",
    "CVE-2012-5961",
    "CVE-2012-5962",
    "CVE-2012-5963",
    "CVE-2012-5964",
    "CVE-2012-5965"
  );
  script_bugtraq_id(57602);
  script_osvdb_id(
    89611,
    90578,
    97337,
    97338
  );
  script_xref(name:"CERT", value:"922681");
  script_xref(name:"EDB-ID", value:"24455");

  script_name(english:"Portable SDK for UPnP Devices (libupnp) < 1.6.18 Multiple Stack-based Buffer Overflows RCE");
  script_summary(english:"Checks the libupnp banner.");

  script_set_attribute(attribute:"synopsis", value:
"A network service running on the remote host is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Portable SDK for UPnP Devices
(libupnp) running on the remote host is prior to 1.6.18. It is,
therefore, affected by multiple remote code execution
vulnerabilities :

  - A stack-based buffer overflow condition exists in the
    unique_service_name() function within file
    ssdp/ssdp_server.c when handling Simple Service
    Discovery Protocol (SSDP) requests that is triggered
    while copying the DeviceType URN. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted SSDP request, to execute arbitrary code.
    (CVE-2012-5958)

  - A stack-based buffer overflow condition exists in the
    unique_service_name() function within file
    ssdp/ssdp_server.c when handling Simple Service
    Discovery Protocol (SSDP) requests that is triggered
    while copying the UDN prior to two colons. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted SSDP request, to execute arbitrary
    code. (CVE-2012-5959)

  - A stack-based buffer overflow condition exists in the
    unique_service_name() function within file
    ssdp/ssdp_server.c when handling Simple Service
    Discovery Protocol (SSDP) requests that is triggered
    while copying the UDN prior to the '::upnp:rootdevice'
    string. An unauthenticated, remote attacker can exploit
    this, via a specially crafted SSDP request, to execute
    arbitrary code. (CVE-2012-5960)

  - Multiple stack-based buffer overflow conditions exist in
    the unique_service_name() function within file
    ssdp/ssdp_server.c due to improper validation of the
    UDN, DeviceType, and ServiceType fields when parsing
    Simple Service Discovery Protocol (SSDP) requests. An
    unauthenticated, remote attacker can exploit these
    issues, via a specially crafted SSDP request, to execute
    arbitrary code. (CVE-2012-5961, CVE-2012-5962,
    CVE-2012-5963, CVE-2012-5964, CVE-2012-5965)");
  # https://community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37da582a");
  script_set_attribute(attribute:"see_also", value:"https://community.rapid7.com/docs/DOC-2150");
  # https://community.rapid7.com/servlet/JiveServlet/download/2150-1-16596/SecurityFlawsUPnP.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54e32505");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130129-upnp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef4b795d");
  # http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-963338.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?698e06b3");
  
  script_set_attribute(attribute:"solution", value:
"Upgrade to libupnp version 1.6.18 or later. If libupnp is used as a
third party library by a different application, contact the vendor of
that application for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Portable UPnP SDK unique_service_name() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libupnp_project:libupnp");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:portable_sdk_for_upnp_project:portable_sdk_for_upnp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("upnp_search.nasl", "http_version.nasl");
  script_require_ports("upnp/server", "Services/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var fix, vuln;
fix = '1.6.18';
vuln = FALSE;

##
# Checks if the given server banner is from a vulnerable
# version of libupnp.  If so, a reporting function is
# called
#
# @param port port number of the service being tested
# @param server server banner advertised on "port"
# @param proto the protocol the port is accessible by (tcp or udp)
##
function _check_libupnp_version(port, server, proto)
{
  local_var ver, report, banner;
  server = chomp(server);
  ver = eregmatch(string:server, pattern:' (Intel|Portable|WindRiver) SDK for UPnP devices */([0-9.]+)', icase:TRUE);

  # the latter two checks are there to account for one-offs where there is no version listed
  # in the server banner, but these specific versions are listed as vulnerable in R7's report
  if (
    (!isnull(ver) && ver_compare(ver:ver[2], fix:fix, strict:FALSE) < 0) ||
    server == 'PACKAGE_VERSION  WIND version 2.8, UPnP/1.0, WindRiver SDK for UPnP devices/' ||
    server == 'Linux/2.6.22.19-40-sigma, UPnP/1.0, Portable SDK for UPnP devices/'
  )
  {
    vuln = TRUE;

    banner = ereg_replace(string:server, pattern:'SERVER: *(.+)', replace:"\1", icase:TRUE);
    report = '\n  Server banner : ' + banner;
    if (!isnull(ver[2])) report += '\n  Installed version : ' + ver[2];
    report += '\n  Fixed version : ' + fix + '\n';

    security_report_v4(port:port,
                       proto:proto,
                       severity:SECURITY_HOLE,
                       extra:report);
  }
}

# check the server string retrieved via UDP 1900 by upnp_search.nasl
servers = get_kb_list('upnp/server');
foreach (server in servers) _check_libupnp_version(port:1900, server:server, proto:'udp');

# check any server strings retrieved via HTTP
www_ports = get_kb_list('Services/www');

foreach port (www_ports)
{
  server = http_server_header(port:port);
  if (isnull(server)) continue;

  _check_libupnp_version(port:port, server:server, proto:'tcp');
}

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');
