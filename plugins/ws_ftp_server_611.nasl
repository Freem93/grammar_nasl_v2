#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(40771);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-0590", "CVE-2008-0608", "CVE-2008-5692", "CVE-2008-5693");
  script_bugtraq_id(27573, 27612, 27654);
  script_xref(name:"OSVDB", value:"41100");
  script_xref(name:"OSVDB", value:"41101");
  script_xref(name:"OSVDB", value:"42046");
  script_xref(name:"OSVDB", value:"51479");
  script_xref(name:"Secunia", value:"28753");
  script_xref(name:"Secunia", value:"28761");
  script_xref(name:"Secunia", value:"28822");

  script_name(english:"Ipswitch WS_FTP Server < 6.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks WS_FTP server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of WS_FTP earlier than 6.1.1.
Such versions are reportedly affected by multiple vulnerabilities :

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
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:ws_ftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("ws_ftp_server_detect.nasl");
  script_require_keys("SMB/WS_FTP_Server/Version");
  exit(0);
}

#

include("global_settings.inc");

version = get_kb_item("SMB/WS_FTP_Server/Version");
if (isnull(version)) exit(1, "The 'SMB/WS_FTP_Server/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for(i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
for(i=max_index(ver); i<4; i++)
  ver[i] = 0;

if(
  ver[0] < 6 ||
  (
    ver[0] == 6 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 1)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "WS_FTP ", version, " is installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected.");
