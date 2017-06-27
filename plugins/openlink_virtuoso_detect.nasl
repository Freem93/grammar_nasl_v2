#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(33588);
  script_version ("$Revision: 1.9 $");

  script_name(english:"Openlink Virtuoso Server Detection");
  script_summary(english:"Detects Openlink Virtuoso Server");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"Openlink Virtuoso Server, a hybrid database server available as a
commercial as well as an open source product is running on the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://virtuoso.openlinksw.com/" );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Virtuoso_Universal_Server" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/25");
 script_cvs_date("$Date: 2011/03/21 13:57:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");	
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl");		
  script_require_ports(1111,"Services/unknown");
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1111);
  if (!port ) exit(0);
  if (!silent_service(port)) exit(0);
}
else port = 1111;

if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

req = 
       mkword(0xbcc1) +  # ? Typically seen at the start of a msg 
       mkword(0xbc05) +
       mkword(0xbc01) +
       mkword(0xbc00) +
       mkbyte(0) +	 # May be end of msg
       mkword(0x15b5) +  # 0xb5 = msg code for size 0x15 == size
       "caller_identification" +
       mkword(0xbcc1) +
       mkword(0xbc01) +
       mkbyte(0) ;	 # May be end of msg

send(socket:soc, data:req);
res = recv(socket:soc, min: 43, length:1024);
if(!res) exit(0);

# Check if we get port number in response.
if (strlen(res) >= 43 && port == substr(res, 15, 18))
{
  # Send SCON command with a bogus account.
  user   = "nessus";	
  length = strlen(user); 	

  req2 = 
    mkword(0xbcc1) +
    mkword(0xbc05) +
    mkword(0xbc01) +
    mkword(0xbc01) +
    mkbyte(0) +	 # May be end of msg
    mkword(0x04b5) + # 0xb5 = msg size code, size 0x04 == size
    "SCON"	       +	
    mkword(0xbcc1) +
    mkbyte(0x04)   + # ?
    mkbyte(0xb5)   + # 0xb5 = msg size code
    mkbyte(length) + # length
    user 	       +
    mkbyte(0xb5)   + # 0xb5 = msg code for size
    mkbyte(length) + # 0xb5 = msg code for size
    user 	+
    mkword(0x0ab5) + # Send Version
    "05.00.3028"   +
    mkword(0xbcc1) +
    mkbyte(0x06)   + # ?
    mkword(0x06b5) + # Send Client Name
    "NESSUS"       +	
    mkword(0x00bd) +
    mkword(0x0c00) +
    mkbyte(0xb4)   +
    mkword(0x0fb5) + # Send Hostname
    "OpenLinkVituoso" +
    mkword(0x05b5) + # 0xb5 = msg code for size
    "Win32"        +
    mkword(0x00b5) + # 0xb5 = msg code for size
    mkword(0x00bc) ;
	
  send(socket:soc, data:req2);
  res = recv(socket:soc, length:10000);

  if (
    strlen(res) == 14 &&                            			# Always 14 bytes
    (
      getword(blob:res, pos:0)  == 0xbcc1 &&  				# Anchor on start of response
      getword(blob:res, pos:12) == 0x00bc &&  				# End of response
      "SQL_BINARY_TIMESTAMP" >!< res          				# Make sure it was not a successful login.      
    ) 							       ||    
    ("LI100: Number of licensed connections exceeded" >< res)  ||    	# Error response on exceeding connection limitation.
    (
      "SQL_TXN_ISOLATION" >< res  && 
      "SQL_BINARY_TIMESTAMP" >< res
    )                                                                   # If we could login successfully (unlikely)
  )
  {
    register_service(port:port, ipproto:"tcp", proto:"openlink-virtuoso");
    security_note(port);
  }
}
close(soc);
