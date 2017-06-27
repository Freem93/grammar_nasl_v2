#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
 script_id(22319);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2011/03/11 21:52:36 $");

 script_name(english:"MSRPC Service Detection");
 script_summary(english:"Detects an MSRPC Service");

 script_set_attribute(attribute:"synopsis", value:
"A DCE/RPC server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Windows RPC service. This service
replies to the RPC Bind Request with a Bind Ack response.

However it is not possible to determine the uuid of this service." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 script_require_ports("Services/unknown");
 script_dependencies("find_service2.nasl", "dcetest.nasl", "smb_nativelanman.nasl");

 exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

if ( ! thorough_tests ) 
{
 kb = get_kb_item("Host/OS/smb");
 if ("Windows" >!< kb)
   exit(0);
}

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

session_init (socket:soc);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"6e657373-7573-7465-6e61-626c65736563", vers:1);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp || (strlen(resp) != 60))
  exit (0);

if ((ord(resp[0]) == 5) &&  # version
    (ord(resp[1]) == 0) &&  # version minor
    (ord(resp[2]) == 12))   # bind ack
{
 register_service(port:port, proto:"dce-rpc");
 security_note (port); 
}
