#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10081);
 script_version("$Revision: 1.43 $");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");

 script_cve_id("CVE-1999-0017");
 script_bugtraq_id(126);
 script_osvdb_id(
  71,
  87439,
  88560,
  88561,
  88562,
  88563,
  88564,
  88565,
  88566,
  88567,
  88568,
  88569,
  88570,
  88571,
  88572
 );
 script_xref(name:"CERT-CC", value:"CA-1997-27");

 script_name(english:"FTP Privileged Port Bounce Scan");
 script_summary(english:"Checks if the remote ftp server can be bounced");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to a FTP server bounce attack.");
 script_set_attribute(attribute:"description", value:
"It is possible to force the remote FTP server to connect to third
parties using the PORT command. 

The problem allows intruders to use your network resources to scan
other hosts, making them think the attack comes from your network.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1995/Jul/46");

 script_set_attribute(attribute:"solution", value:"See the CERT advisory in the references for solutions and workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/07/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_family(english:"FTP"); 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_kibuv_worm.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/ncftpd");
 exit(0);
}

#
# The script code starts here :
#
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

port = get_ftp_port(default: 21);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");


soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  ip = get_host_ip();
  last = ereg_replace(string:ip,
  		    pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)$",
		    replace:"\1");
  last = (int(last) + 42) % 256;
  ip = strcat("169,254,", rand() % 256, ",", rand() % 256);
  ip = ereg_replace(string:ip, pattern:"\.", replace:",");
  ip = ereg_replace( pattern:"([0-9]*,[0-9]*,[0-9]*,)[0-9]*$",
  			replace:"\1",
			string:ip);
  ip = strcat(ip, last);			
  h  = str_replace(string:ip, find:',', replace:'.');
  command = strcat('PORT ', ip, ',42,42\r\n');
  send(socket:soc, data:command);
  code = ftp_recv_line(socket:soc);
  if ( ! code ) {
	close(soc);
	exit(0);
  }
  code = str_replace(string:code, find:'\r', replace:'');
  p = 42*256+42;
  if ( code =~ "^200" )
   security_hole(port:port, extra:'The following command, telling the server to connect to ' + h + ' on port ' + p + ':\n\n' + ( command - '\r')  + '\nproduced the following output:\n\n' + code);
 }
 close(soc);
