#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14256);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");

 script_cve_id("CVE-2004-1439");
 script_bugtraq_id(10834);
 script_osvdb_id(8273);
 
 script_name(english:"BlackJumboDog FTP Server Multiple Command Overflow");
 script_summary(english:"Determines the version of BlackJumboDog");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BlackJumboDog FTP server.

This FTP server fails to properly check the length of parameters in 
multiple FTP commands, most significant of which is USER, resulting 
in a stack overflow. 

With a specially crafted request, an attacker can execute arbitrary code 
resulting in a loss of integrity, and/or availability." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.6.2 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 
 script_dependencies("find_service2.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports(21, "Services/ftp");
 exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1, "No FTP banner on port "+port+".");
	
#220 FTP ( BlackJumboDog(-RAS) Version 3.6.1 ) ready
#220 FTP ( BlackJumboDog Version 3.6.1 ) ready

if( "BlackJumboDog" >< banner ) 
{
  if (safe_checks())
  {
	if ( egrep(pattern:"^220 .*BlackJumboDog.* Version 3\.([0-5]\.[0-9]+|6\.[01]([^0-9]|$))", string:banner ) )
	security_hole(port);
  }
  else
  {
       req1 = string("USER ", crap(300), "\r\n");
       soc=open_sock_tcp(port);
 	if ( ! soc ) exit(1, "Cannot connect to TCP port "+port+".");
       send(socket:soc, data:req1);    
       close(soc);
       sleep(1);
       soc2 = open_sock_tcp(port);
	if (! soc2 || ! ftp_recv_line(socket:soc))
       {
	  security_hole(port);
	}
	else close(soc2);
	exit(0);
  }
}
