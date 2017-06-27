#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(15857);
 script_bugtraq_id(11772);
 script_osvdb_id(12509);
 script_cve_id("CVE-2004-1135");
 script_version ("$Revision: 1.13 $");

 script_name(english:"WS_FTP Server Multiple Command Remote Overflow DoS");
 script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by a buffer overflow vulnerability");
 script_set_attribute(attribute:"description", value:"
According to its version number, the remote WS_FTP server is
vulnerable to multiple buffer overflows which may be used by an
attacker to execute arbitrary code on the remote system.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'WS-FTP Server 5.03 MKD Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/29");
 script_cvs_date("$Date: 2012/05/11 21:29:20 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 summary["english"] = "Check WS_FTP server version";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

if (egrep(pattern:"WS_FTP Server ([0-4]\.|5\.0\.[0-3][^0-9])", string: banner))
	security_hole(port);
