#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14195);
 script_cve_id("CVE-2004-0695");
 script_bugtraq_id(10720);
 script_osvdb_id(7794);
 script_version ("$Revision: 1.17 $");
 
 script_name(english:"4D WebStar Pre-authentication FTP Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a buffer overflow condition in the remote version of 4D
WebStar FTP Server installed on the remote host.  An attacker may
exploit this flaw to execute arbitrary code on the remote host with
the privileges of the FTP server (root)." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/130");
 script_set_attribute(attribute:"solution", value:
"Upgrade to 4D WebStar 5.3.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'WebSTAR FTP Server USER Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/13");
 script_cvs_date("$Date: 2016/09/22 15:18:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for 4D FTP Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/www", 80, "Services/ftp", 21);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same host
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 port = get_ftp_port(default: 21);
 ftpbanner = get_ftp_banner(port:port);
 if (egrep(string:ftpbanner, pattern:"^220 FTP server ready\."))
 { 
  security_hole(port);
 }
}
