#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(48214);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/08 15:34:22 $");

  script_bugtraq_id(41015);
  script_osvdb_id(65960);

  script_name(english:"Wing FTP Server < 3.2.0 PORT Command DoS");
  script_summary(english:"Checks version in Wing FTP Server FTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service issue.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Wing
FTP Server earlier than 3.2.0.  Such versions are reportedly affected
by a denial of service vulnerability.  By sending a specially crafted
'PORT' command with an invalid parameter, it may be possible for an
attacker to crash the service.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2193b10");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e5117d4");
  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/serverhistory.htm" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wing FTP Server 3.2.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "http_version.nasl");
  script_require_ports("Services/ftp", 21, "Services/www", 5466);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("http.inc");

port = get_ftp_port(default: 21);

version = '';
source  = '';
service = '';

banner = get_ftp_banner(port:port);
if (banner && "Wing FTP Server" >< banner)
{
  source = banner; 
  service = "FTP";
  matches = eregmatch(pattern:" Wing FTP Server ([0-9.]+)", string:banner);

  if (matches) version = matches[1];
}

# Try to get the admin interface banner only under paranoid mode 
if (!version && report_paranoia > 1)
{
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
        if(matches)
        {
          version = matches[1];
          break;
        }
      }
    }
  } 
}

if (!source) exit (0, "Wing FTP Server is not running on the remote host.");

if (!version) exit(1, "It was not possible to extract Wing FTP Server version listening on the remote host.");

if (ver_compare(ver:version, fix:'3.2.0',strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.2.0'+ 
             '\n  Service            : ' + service +
             '\n  Version source     : ' + source;
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else
  exit(0, "Wing FTP Server version "+  version + " is running on port "+ port + " and hence is not affected.");
