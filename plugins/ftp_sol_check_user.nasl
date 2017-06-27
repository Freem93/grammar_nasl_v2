#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10653);
 script_bugtraq_id(2564);
 script_osvdb_id(72);
 script_version ("$Revision: 1.18 $");
 script_name(english:"Solaris FTP Daemon CWD Command Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to an account enumeration attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the existence of a user on the remote
system by issuing the command CWD ~<username>, even before logging in.
An attacker can exploit this flaw to determine the existence of known
vulnerable accounts." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/11");
 script_cvs_date("$Date: 2011/03/11 21:52:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"CWD ~root before logging in");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
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

soc = open_sock_tcp(port);
if (! soc) exit(1);

	data = string("CWD ~nonexistinguser\r\n");
  	send(socket:soc, data:data);
  	a = ftp_recv_line(socket:soc);
  	if(egrep(pattern:"^550 Unknown user name after ~",
  	   string:a))security_warning(port);
  	ftp_close(socket:soc);

