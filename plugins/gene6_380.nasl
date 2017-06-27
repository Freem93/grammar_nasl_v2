#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21324);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-2172");
  script_bugtraq_id(17810);
  script_osvdb_id(25238);
 
  script_name(english:"Gene6 FTP Server Multiple Command Remote Overflows");
  script_summary(english:"Checks for buffer overflow vulnerabilities in Gene6 FTP Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by buffer overflow flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using Gene6 FTP Server, a professional
FTP server for Windows. 

According to its banner, the version of Gene6 FTP Server installed on
the remote host contains buffer overflow vulnerabilities that can be
exploited by an authenticated, possibly anonymous, user with
specially crafted 'MKD', 'RMD', 'XMKD', and 'XRMD' commands to crash
the affected application or execute arbitrary code on the affected
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/432839/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.g6ftpserver.com/forum/index.php?showtopic=2515" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gene6 FTP Server version 3.8.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/03");
 script_cvs_date("$Date: 2011/09/22 21:51:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_ftp_port(default: 21);


banner = get_ftp_banner(port:port);
if (
  banner &&
  egrep(pattern:"^220[- ]Gene6 FTP Server v([0-2]\.|3\.([0-6]\..*|7\.0))", string:banner)
) security_hole(port);
