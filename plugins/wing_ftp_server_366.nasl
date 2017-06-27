#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(49068);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_bugtraq_id(42736);
  script_osvdb_id(67442);
  script_xref(name:"Secunia", value:41040);

  script_name(english:"Wing FTP Server < 3.6.6 DoS");
  script_summary(english:"Checks version in Wing FTP Server HTTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Wing
FTP Server earlier than 3.6.6. Such versions reportedly fail to handle
certain specially crafted HTTP requests. An attacker could exploit this 
issue to trigger a denial of service condition, and crash the remote
service.");

  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/serverhistory.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wing FTP Server 3.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "ftpserver_detect_type_nd_version.nasl","os_fingerprint.nasl");
  script_require_ports("Services/www", 5466, "Services/ftp", 21);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("http.inc");

# Only affects Windows installs.
if(report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (os && "Windows" >!< os) exit(0, "The remote OS is not Windows.");
}

version = '';
source  = '';
service = '';

ports = add_port_in_list(list:get_kb_list("Services/www"), port:5466);
foreach port (ports)
{
  banner = get_http_banner(port:port);
  if (banner && "Server:" >< banner)
  {
    server = chomp(egrep(string: banner, pattern: "^Server:"));
    if ("Wing FTP" >< server)
    {
      source = server;
      service = "HTTP";
      matches = eregmatch(pattern:"Wing FTP Server/([0-9.]+)", string:server);
      if (matches)
      {
        version = matches[1];
        break;
      }
    }
  }
}

if(!version && report_paranoia < 2)
exit (1, "The affected HTTP service was not detected on port(s) "+join(sep:" & ", ports)+".");

# Look for FTP banner, if we are in paranoid mode
if (!version)
{
  port = get_ftp_port(default:21);
  banner = get_ftp_banner(port:port);
  if (!banner) exit(1, "The FTP server on port "+port+" does not return a banner.");
  if ("Wing FTP Server" >!< banner) exit(0, "The banner from the FTP server on port "+port+" is not from Wing FTP Server.");

  source = banner;
  service = "FTP"; 
  matches = eregmatch(pattern:" Wing FTP Server ([0-9.]+)", string:banner);
  if (matches) version = matches[1];
}

if(!source)
exit (0, "Wing FTP Server is not running on the remote host.");

if(!version)
  exit(1, "It was not possible to extract Wing FTP Server version listening on the remote host.");

if (ver_compare(ver:version, fix:'3.6.6',strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.6.6' +
             '\n  Service            : ' + service +
             '\n  Version source     : ' + source +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else exit(0, "Wing FTP Server version "+  version + " is running on port "+ port + " and hence is not affected."); 
