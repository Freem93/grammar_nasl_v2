#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10471);
 script_bugtraq_id(1452);
 script_osvdb_id(370);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-2000-0640");
 script_name(english:"GuildFTPd Traversal Arbitrary File Enumeration");
 script_summary(english:"GuildFTPd check");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server can be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. This is caused by the server responding with
different error messages depending on if the file exists or not.

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/guildftpd-dir-adv.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GuildFTPd 0.999.6 or later, as this reportedly fixes the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/08");
 script_cvs_date("$Date: 2011/03/11 20:33:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

 login = get_kb_item("ftp/login");
 pass  = get_kb_item("ftp/password");
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    pasv_port = ftp_pasv(socket:soc);
    soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
    req = 'RETR ../../../../../../nonexistent_at_all.txt\r\n';
  
    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);
  
    if("550 Access denied" >< r)
    {
    
     close(soc2);
     pasv_port = ftp_pasv(socket:soc);
     soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
     req = 'RETR ../../../../../../../../autoexec.bat\r\n';
     send(socket:soc, data:req);
     r =  recv_line(socket:soc, length:4096);
     r2 = recv_line(socket:soc, length:4096);
     r = strcat(r, r2);
     if("425 Download failed" >< r)security_hole(port);
     close(soc2);
    }
    ftp_close(socket: soc);
    exit(0);
    }
   }
  else
    {
     ftp_close(socket: soc);
    }   
  }
  
 #
 # We could not log in. Then we'll just attempt to 
 # grab the banner and check for version <= 0.97
 #
r = get_ftp_banner(port: port);
  if("GuildFTPD" >< r)
  {
   r = strstr(r, "Version ");
   if(egrep(string:r, pattern:".*Version 0\.([0-8].*|9[0-7]).*"))
  {
    security_hole(port);
  }
 }
