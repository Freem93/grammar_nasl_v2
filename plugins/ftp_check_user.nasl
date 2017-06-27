#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
if (description)
{
 script_id(10082);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2013/12/04 19:29:57 $");
 script_name(english:"FTPd CWD Command Account Enumeration");
 script_summary(english:"Checks for the existence of a user");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable by an account-enumeration attack.");
 script_set_attribute(attribute:"description", value:
"It is possible to determine the existence of a user on the remote
system by issuing the command CWD ~<username>. 

An attacker may use this to determine the existence of known to be
vulnerable accounts (like guest) or to determine which system you are
running.");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);

anon = get_kb_item("ftp/"+port+"/anonymous");
if (!anon) exit(0, "The FTP server listening on port "+port+" rejects anonymous logins.");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (ftp_authenticate(socket:soc, user:"anonymous",pass:"nessus@"))
{
  data = string("CWD ~root\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  data = string("QUIT\r\n");
  send(socket:soc, data:data);
  close(soc);

  if ("550 /" >< a)
  {
    security_warning(port:port, extra:'CWD ~root returns :' + '\n\n' + a);
    exit(0);
  }
}
else close(soc);
exit(0, "The FTP server listening on port "+port+" is not affected.");
