#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(50676);
 script_version("$Revision: 1.4 $");
 script_cvs_date("$Date: 2011/05/24 20:37:07 $");

 script_name(english:"BitTorrent / uTorrent Detection");
 script_summary(english:"BitTorrent detection");

 script_set_attribute(attribute:"synopsis", value:
"A file-sharing service is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BitTorrent or uTorrent, peer-to-peer file
sharing applications.

Note that, due to the peer-to-peer nature of these applications, any
user connecting to the BitTorrent network may consume a large amount
of bandwidth." );
 script_set_attribute(attribute:"see_also", value:"http://www.bittorrent.com/");
 script_set_attribute(attribute:"see_also", value:"http://www.utorrent.com/");
 script_set_attribute(attribute:"solution", value:
"Make sure that the use of this program agrees with your
organization's acceptable use and security policies. 

Note that filtering traffic to or from this port is not a sufficient
solution since the software can use a random port.");
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_dependencie("find_service1.nasl", "embedded_web_server_detect.nasl");
 script_require_ports("Services/www");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function send_data(port,data,udp)
{
  local_var soc,res;
  
  if(udp == 1)
  {
    if (! get_udp_port_state(port)) return NULL;
    soc = open_sock_udp(port);
  }
  else
  {
    if (! get_tcp_port_state(port)) return NULL;
    soc = open_sock_tcp(port);
  } 
  if ( ! soc ) return NULL;
   
  send(socket:soc, data:data);

  res = recv(socket:soc,length:4096);
  close(soc);
  
  return res;
}

function udp_sendrecv(port,data)
{
  return send_data(port:port,data:data,udp:1);
}


function report_detection_and_exit(port,webui_enabled)
{
  local_var extra;
  if (report_verbosity > 0)
  {
    if (webui_enabled) extra = '\nThe WebUI is available at :\n\n' + build_url(qs:'/gui', port:port) + '\n';
    else extra = '\nThe WebUI on this port is currently disabled.\n'; 
    security_note(port:port,extra:extra);
  }
  else security_note(port:port,extra:extra);

  security_note(port:port,protocol:'udp');
  register_service(port:port, ipproto:"udp", proto:"bittorrent");
  register_service(port:port, ipproto:"tcp", proto:"bittorrent");
  # bittorrent is not a web server
  declare_broken_web_server(port: port, reason: 'bittorrent is not a real www server\n'); 
  exit(0);
}

function bt_udp_test(port)
{
  local_var data, sig1, sig2, res;
  
  sig1 = '\xde\xad\xbe\xef';
  sig2 = '\xf0\x0d';
  
  data = sig1 + rand_str(length:15) + sig2 + rand_str(length:2);
  
  res = udp_sendrecv(port:port,data:data);
  if(isnull(res)) return FALSE;
  
  # response:
  # 0000  de ad be ef 00 00 00 00-00 00 00 00 00 00 00 00  ................
  # 0010  00 00 03 79 83 f0 0d                             ...y...

  if(strlen(res) >= 0x17              &&
     substr(res, 0 , 3)       == sig1 &&
     substr(res, 0x15, 0x16)  == sig2)
        return TRUE;
   
  return FALSE;
}

function webui_response(port)
{
  local_var res;
  
  res = http_send_recv3(method:'GET', port:port, item:'/gui', exit_on_fail:TRUE);

  if (isnull(res)) return res;
  else return res[0] + res[1] + res[2];
}


port = get_http_port(default: 80, embedded: TRUE, dont_break: 1);
banner = get_http_banner(port:port, exit_on_fail:TRUE, broken:TRUE);
 
# only test www ports that doesn't appear to have
# a real www server running 
if(("Server:" >!< banner) && 
    (port >= 10000 && port <= 65000)) 
{  
  # check for HTTP GET response
  res = webui_response(port:port);
  if(! isnull(res))
  {
    if(res =~'^HTTP/1\\.[01] 401 Unauthorized.+(Bit|u)Torrent')
      report_detection_and_exit(port:port, webui_enabled:TRUE);
    else if(res =~'^HTTP/1\\.[01] 400 ERROR.+invalid request')
    {      
      if(bt_udp_test(port:port))
        report_detection_and_exit(port:port, webui_enabled:FALSE);
    }
  }
}

exit(0, 'The BitTorrent/uTorrent WebUI was not detected on port '+port+'.');
