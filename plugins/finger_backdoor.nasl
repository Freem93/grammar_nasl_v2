#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10070);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/10/21 20:34:20 $");

 script_name(english:"Finger Backdoor Detection");
 script_summary(english:"Finger cmd_root@host backdoor");

 script_set_attribute(attribute:"synopsis", value:"The remote finger daemon appears to be a backdoor.");
 script_set_attribute(attribute:"description", value:
"The remote finger daemon seems to be a backdoor, as it seems to react
to the request :

 cmd_rootsh@target

If a root shell has been installed as /tmp/.sh, then this finger
daemon is definitely a trojan, and this system has been compromised.");
 script_set_attribute(attribute:"solution", value:
"Audit the integrity of this system, since it seems to have been
compromised");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");

 script_family(english:"Backdoors");

 script_dependencies("find_service1.nasl", "finger.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/finger", 79);

 exit(0);
}

include("audit.inc");
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("root\r\n");
  send(socket:soc, data:buf);
  data_root = recv(socket:soc, length:2048);
  close(soc);
  if(data_root)
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    buf = string("cmd_rootsh\r\n");
    send(socket:soc, data:buf);
    data_cmd_rootsh = recv(socket:soc, length:2048);
    close(soc);

    if(!data_cmd_rootsh)
    {
     buf = string("version\r\n");
     soc = open_sock_tcp(port);
     if(!soc)exit(0);
     send(socket:soc, data:buf);
     data_version = recv(socket:soc, length:2048);
     close(soc);

     if("CFINGERD" >< data_version) exit(0); #false positive
     if((data_root == data_version)) exit(0); #false positive, same answer all the time
     security_hole(port);
    }
   }
  }
 }
}
