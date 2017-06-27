#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10281);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2014/01/29 12:29:18 $");

 script_name(english:"Telnet Server Detection");
 script_summary(english:"Telnet Server Detection");

 script_set_attribute(attribute:"synopsis", value:"A Telnet server is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Telnet server, a remote terminal
server.");
 script_set_attribute(attribute:"solution", value:"Disable this service if you do not use it.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencie("find_service1.nasl", "telnet.nasl");
 script_require_ports("Services/telnet", 23);

 exit(0);
}


#
# The script code starts here
#
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("telnet2_func.inc");


global_var banner, sb;
global_var then;


function get_telnet_banner(port)
{
  sb = string("Services/telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  if ( ! telnet2_init(port: port, timeout: 3 * get_read_timeout()) ) return NULL;
  then = unixtime();
  banner = NULL;
  telnet_loop();
  return banner;
}

function filter_banner()
{
 local_var i, n, str;

 str = _FCT_ANON_ARGS[0];
 n = strlen(str);
 for ( i = 0 ; i < n ; i ++ )
 {
   if ( str[i] == '\n' || str[i] == '\r' || str[i] == '\t' ) continue;
   if ( ord(str[i]) < 0x20 || ord(str[i]) > 0x7e ) str[i] = '.';
 }
 return str;
}

function telnet_callback()
{
 local_var str;
 local_var sbanner;

 str = _FCT_ANON_ARGS[0];
 if ( str != NULL ) banner += str;
 else if ( unixtime() > then + get_read_timeout() ||
	   "ogin:" >< banner ||
	   "word:" >< banner ||
	   "sername:" >< banner ||
	   strlen(banner) > 512 )
 {
	if ( banner ) {
	 sbanner = str_replace(find:raw_string(0), replace:'', string:banner);
	 if ( strlen(sbanner) ) replace_kb_item(name: sb, value:sbanner);
	}
	return -1;
 }
 return 0;
}

function test(port)
{
  local_var	banner, trp, b, report;

  if (! get_port_state(port)) return 0;
  if (service_is_unknown(port: port))
  {
    b = get_unknown_banner2(port: port);
    if (isnull(b)) return 0;
    if (b[1] != 'spontaneous') return 0;
    banner = b[0];
    if ( strlen(banner) <= 2 || ord(banner[0]) != 255 ||
       	 ord(banner[1]) < 251 || ord(banner[1]) > 254 )
      return 0;
    register_service(port: port, proto: "telnet");
  }
  else
    if (! verify_service(port: port, proto: "telnet"))
      return 0;

  banner = get_telnet_banner(port: port);
  if(strlen(banner) && "CCProxy Telnet Service" >!< banner)
  {
   if (report_verbosity > 0)
   {
    report = string(
           "Here is the banner from the remote Telnet server :\n",
           "\n",
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
           filter_banner(banner), "\n",
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
         );
    security_note(port:port, extra:report);
   }
   else security_note(port);
   return 1;
  }
  return 0;
}

l = add_port_in_list(port: 23, list: get_kb_list("Services/telnet"));

foreach port (l)
  test(port: port);
