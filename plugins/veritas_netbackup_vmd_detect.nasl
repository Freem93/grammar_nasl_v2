#
# (C) Tenable Network Security, Inc.
#

# Only works if the remote vmd can resolve hostname and allow anoymous
# connections


include("compat.inc");

if (description)
{
 script_id(20181);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2012/08/23 21:13:31 $");

 script_name(english:"VERITAS NetBackup Volume Manager Detection");

 script_set_attribute(attribute:"synopsis", value:
"A backup software is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the VERITAS NetBackup Volume Manager
service." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec_veritas:netbackup");
script_end_attributes();

 script_summary(english:"Determine if a remote host is running VERITAS NetBackup Volume Manager Service");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_require_ports (13701, "Services/unknown");
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");


function check (socket, port)
{
 local_var data, line, len, buf;

 data = '661292220 9 1 1\n';
 send (socket:socket, data:data);

 len = recv (socket:socket, length:4, min:4);
 if (strlen(len) != 4)
   exit (0);

 len = getdword (blob:len, pos:0);
 if ( (len <= 0) || (len >= 65535) )
   exit (0);

 buf = recv (socket:socket, length:len, min:len);
 if (strlen(buf) != len)
   exit (0);

 if (egrep (pattern:"^REQUEST ACKNOWLEDGED", string:buf))
 {
  security_note (port);
  set_kb_item (name:"VERITAS/NetBackupVolumeManager", value:port);
  register_service (port:port, proto:"vmd");
 }
}


port = 13701;
if (get_port_state(port))
{
 soc = open_sock_tcp (port);
 if (soc)
   check (socket:soc, port:port);
}

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
 port = get_unknown_svc();
 if (port == 13701 || ! port ) exit (0);

 if (get_port_state(port))
 {
  soc = open_sock_tcp (port);
  if (soc)
    check (socket:soc, port:port);
 }
}
