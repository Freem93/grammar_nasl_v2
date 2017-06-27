#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11011);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2015/06/02 17:53:33 $");

 script_name(english:"Microsoft Windows SMB Service Detection");
 script_summary(english:"Checks availability of port 445 / 139");

 script_set_attribute(attribute:"synopsis", value:"A file / print sharing service is listening on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote service understands the CIFS (Common Internet File System)
or Server Message Block (SMB) protocol, used to provide shared access
to files, printers, etc between nodes on a network.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(139, 445, "/tmp/settings");
 script_dependencie("ping_host.nasl", "nessus_product_setup.nasl");
 exit(0);
}
#
# The script code starts here
#

include("smb_func.inc");

# Plugin is run by the local Windows Nessus Agent
if (get_kb_item("nessus/product/agent"))
{
  # Note: many Windows credentialed plugins call smb_kb_transport()
  # to get the SMB port, and the smb_kb_transport() function
  # queries KB 'SMB/transport'.
  #
  # Many of these plugins will exit (prematurely) if they can't find
  # a SMB port. Here we explicitly set the SMB port, so that these
  # plugins can continue.
  #
  # Satisfy script_require_keys("SMB/transport")
  set_kb_item(name:"SMB/transport", value:445);

  # Satisfy script_require_ports(445)
  replace_kb_item(name:"Ports/tcp/445", value: TRUE);

  # scanner_add_port(port:445, proto:"tcp");
  exit(0);
}


function will_scan_port()
{
 local_var target;
 local_var pref;
 local_var port;
 local_var i;


 target = _FCT_ANON_ARGS[0];
 if ( NESSUS_VERSION =~ "^3\." ) return TRUE; # Bug in older versions
 if ( isnull(target) ) return TRUE;

 pref = get_preference("unscanned_closed");
 if ( isnull(pref) || pref != "yes" ) return TRUE;

 for ( i = 0 ; TRUE ; i ++ )
 {
 port = scanner_get_port(i);
 if ( isnull(port) ) break;
 if ( port == target ) return TRUE;
 if ( port >  target ) break;
 }

 return FALSE;
}


flag = 0;

if( !get_kb_item("Host/scanned") ||  get_port_state(445))
{
 if ( will_scan_port(445) )
 {
 soc = open_sock_tcp(445);
 if(soc){
 if ( ! get_kb_item("Ports/tcp/445") )
	set_kb_item(name:"Ports/tcp/445", value:TRUE);
 session_init(socket:soc);
 ret = smb_negotiate_protocol ();
 close(soc);
 if(ret){
	set_kb_item(name:"Services/cifs", value:445);
	set_kb_item(name:"Known/tcp/445", value:"cifs");
	security_note(port:445, extra:'\nA CIFS server is running on this port.\n');
	set_kb_item(name:"SMB/transport", value:445);
	flag = 1;
      }
   }
 }
}


if( !get_kb_item("Host/scanned") || get_port_state(139))
{
  if ( will_scan_port(139) )
  {
  soc = open_sock_tcp(139);
  if(soc){
 	 if ( ! get_kb_item("Ports/tcp/139") )
		set_kb_item(name:"Ports/tcp/139", value:TRUE);
          session_init (socket:soc);
          called_name = netbios_name (orig:string("Nessus", rand()));
          calling_name = netbios_name (orig:NULL);

          data = called_name + raw_byte (b:0) +
                 calling_name + raw_byte (b:0);
          r = netbios_sendrecv (type:0x81, data:data);
          close(soc);
          if(r && (ord(r[0]) == 0x82 || ord(r[0]) == 0x83)) {
		set_kb_item(name:"Services/smb", value:139);
		set_kb_item(name:"Known/tcp/139", value:"smb");
		security_note(port:139, extra:'\nAn SMB server is running on this port.\n');
    		if(!flag)set_kb_item(name:"SMB/transport", value:139);
		}
	}
 }
}

