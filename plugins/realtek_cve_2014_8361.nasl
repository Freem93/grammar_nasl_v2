#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83185);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2014-8361");
  script_bugtraq_id(74330);
  script_osvdb_id(121276);
  script_xref(name:"ZDI", value:"ZDI-15-155");
  script_xref(name:"EDB-ID", value:"37169");

  script_name(english:"Realtek SDK miniigd SOAP Service RCE");
  script_summary(english:"Checks the banners.");

  script_set_attribute(attribute:"synopsis",value:
"A software development kit running on the remote device is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description",value:
"According to its banner, the Realtek Software Development Kit is
running on the remote device. It is, therefore, affected by a flaw in
the miniigd SOAP service due to a failure to properly sanitize user
input when handling NewInternalClient requests. An unauthenticated,
remote attacker, using a crafted request, can exploit this to execute
arbitrary code with root level privileges.");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-15-155/");
  script_set_attribute(attribute:"solution",value:
"There is currently no fix available. As a workaround, restrict access
to vulnerable devices.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Realtek SDK Miniigd UPnP SOAP Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:realtek:realtek_sdk");
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
vuln = FALSE;

##
# Checks if the given server banner is from a vulnerable
# version of realtek upnpd.  If so, a reporting function is
# called
#
# @param port port number of the service being tested
# @param server server banner advertised on "port"
# @param proto the protocol the port is accessible by (tcp or udp)
##
function _check_realtek_version(port, server, proto)
{
  local_var ver, report, banner;
  server = chomp(server);
  ver = eregmatch(string:server, pattern:"realtek/v((0(\.[0-9.]+)?|1\.[0-3](\.[0-9.]+)?|1)$)", icase:TRUE);

  if (!isnull(ver))
  {
    vuln = TRUE;

    banner = ereg_replace(string:server, pattern:'SERVER: *(.+)', replace:"\1", icase:TRUE);
    report =
      '\n  Server banner     : ' + banner +
      '\n  Installed version : ' + ver[1] + '\n';

    security_report_v4(port:port,
                       proto:proto,
                       severity:SECURITY_HOLE,
                       extra:report);
  }
}

# check the server string retrieved via UDP 1900 by upnp_search.nasl
servers = get_kb_list('upnp/server');
foreach(server in servers) _check_realtek_version(port:1900, server:server, proto:'udp');

# check any server strings retrieved via HTTP
www_ports = get_kb_list('Services/www');

if(!vuln && isnull(www_ports))
  audit(AUDIT_HOST_NOT, 'affected');

foreach port (www_ports)
{
  server = http_server_header(port:port);
  if (empty_or_null(server)) continue;

  _check_realtek_version(port:port, server:server, proto:'tcp');
}

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');
