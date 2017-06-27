#
# written by Gareth Phillips - SensePost (www.sensepost.com)
# GPLv2
#
# Changes by Tenable:
#  - Fixed regex
#  - Changed plugin family (8/15/09)
#  - Revised description and added CPE (12/03/12)


include("compat.inc");

if(description)
{
 script_id(18627);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2005-1415");
 script_bugtraq_id (13454);
 script_osvdb_id(16049);

 script_name(english:"GlobalSCAPE Secure FTP Server User Input Overflow");
 script_summary(english:"GlobalSCAPE Secure FTP Server User Input Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GlobalSCAPE Secure FTP Server.

GlobalSCAPE Secure FTP Server 3.0.2 and prior versions are affected by
a buffer overflow due to mishandling the user-supplied input. 

An attacker would first need to authenticate to the server before they
can execute arbitrary commands." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/May/12" );
 script_set_attribute(attribute:"see_also", value:"http://www.globalscape.com/gsftps/history.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GlobalSCAPE Secure FTP 3.0.3 Build 4.29.2005 or later as
this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'GlobalSCAPE Secure FTP Server Input Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/01");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:globalscape:secure_ftp_server");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 SensePost");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}




#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

ftpbanner = get_ftp_banner(port:port);
if ( ftpbanner && egrep(pattern:"^220 GlobalSCAPE Secure FTP Server \(v. 3(.0|\.0\.[0-2])\)",string:ftpbanner) )security_hole(port);
