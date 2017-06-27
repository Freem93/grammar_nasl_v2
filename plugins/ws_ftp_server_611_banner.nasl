#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(40772);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-0590", "CVE-2008-0608", "CVE-2008-5692", "CVE-2008-5693");
  script_bugtraq_id(27573, 27612, 27654);
  script_osvdb_id(41100, 41101, 42046, 51479);
  script_xref(name:"Secunia", value:"28753");
  script_xref(name:"Secunia", value:"28761");
  script_xref(name:"Secunia", value:"28822");

  script_name(english:"Ipswitch WS_FTP Server < 6.1.1 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks version in FTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
WS_FTP earlier than 6.1.1.  Such versions are reportedly affected by
multiple vulnerabilities :

  - Improper handling of UDP packets within the FTP log 
    server may allow an attacker to crash the affected 
    service. (CVE-2008-0608)

  - There is a buffer overflow vulnerability in the SSH 
    Server service that can be triggered when handling 
    arguments to the 'opendir' command. (CVE-2008-0590)

  - An attacker can exploit a vulnerability in the
    'FTPLogServer/LogViewer.asp' script to gain access to
    the log viewing interface. (CVE-2008-5692)" );
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitchft.com/support/ws_ftp_server/releases/wr611.asp" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/487506/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/487441/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server 6.1.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:ws_ftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/wsftp");
  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1, "No FTP banner on port "+port);
if ("WS_FTP Server" >!< banner) exit(0, "Banner on port "+port+" doesn't look like WS_FTP.");

version = strstr(banner, " WS_FTP Server ") - " WS_FTP Server ";
version = ereg_replace(string:version, pattern:"^([0-9\.]+).*", replace:"\1");

if (version =~ "^([0-5]\.|6\.(0(\.[0-9\.]+|$)|1([^\.]|\.0)))")
{
  if (report_verbosity > 0)
  {
    report = strcat(
      '\n',
      'WS_FTP version ', version, ' appears to be running on the remote host based\n',
      'on the following banner :\n',
      '\n',
      '  ', banner, '\n',
      '\n'
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else exit(0, 'The host is not affected.');
