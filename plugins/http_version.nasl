#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#
#
# @@NOTE: The output of this plugin should not be changed
#

# Changes by Tenable:
# - Revised plugin title (10/08/10)

include("compat.inc");

if (description)
{
 script_id(10107);
 script_version("$Revision: 1.123 $");
 script_cvs_date("$Date: 2016/02/19 18:54:50 $");

 script_name(english:"HTTP Server Type and Version");
 script_summary(english:"HTTP Server type and version");

 script_set_attribute(attribute:"synopsis", value:"A web server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"This plugin attempts to determine the type and the version of the
remote web server.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 H. Scholz & Contributors");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_login.nasl", "httpver.nasl", "no404.nasl", "www_fingerprinting_hmap.nasl", "webmin.nasl", "embedded_web_server_detect.nasl", "fake_http_server.nasl", "broken_web_server.nasl", "skype_detection.nasl", "www_server_name.nasl", "restricted_web_pages.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

#
# The script code starts here
#
global_var	port;

function get_apache_version()
{
 local_var req, soc, r, v;

 req = http_get(item:"/nonexistent_please_dont_exist", port:port);
 soc = http_open_socket(port);
 if(!soc) return NULL;
 send(socket:soc, data:req);
 r = egrep(pattern:"<ADDRESS>.*</ADDRESS>", string:http_recv(socket:soc));
 http_close_socket(soc);
 if(!r)
  return NULL;

 v = ereg_replace(string:r, pattern:"<ADDRESS>(Apache/[^ ]*).*", replace:"\1");
 if( r == v )
  return NULL;
 else return v;
}


function get_domino_version()
{
 local_var req, soc, r, v;
 local_var whole_response, r_from_webroot, v_from_webroot;
 req = http_get(item:"/nonexistentdb.nsf", port:port);
 soc = http_open_socket(port);
 if(!soc) return NULL;
 send(socket:soc, data:req);
 r = egrep(pattern:".*Lotus-Domino .?Release", string:http_recv(socket:soc));
 http_close_socket(soc);
 v = NULL;
 if(r != NULL)v = ereg_replace(pattern:".*Lotus-Domino .?Release ([^ <]*).*", replace:"Lotus-Domino/\1", string:r);
 if(r == NULL || v == r )
 {
   # Attempt to get something from the '/' page which
   # contains a rough version number
   req = http_get(item:"/", port:port);
   soc = http_open_socket(port);
   if(!soc) return NULL;
   send(socket:soc, data:req);
   whole_response = http_recv(socket:soc);
   r_from_webroot = egrep(pattern:">Domino (Administrator [0-9.]+|[0-9.]+ Administrator) Help<", string:whole_response);
   http_close_socket(soc);

   v_from_webroot = NULL;
   if(r_from_webroot != NULL)
   {
     # Just an extra check since we're relying on strings
     # in HTML below; make sure Server header is good
     if ("Server: Lotus-Domino" >< whole_response)
     {
       # Early versions
       if ("Domino Administrator " >< r_from_webroot)
         v_from_webroot = ereg_replace(pattern:".*>Domino Administrator ([0-9.]+) Help<.*", replace:"Lotus-Domino/\1", string:r_from_webroot);
       # Later versions (9x)
       if ("Administrator Help" >< r_from_webroot)
         v_from_webroot = ereg_replace(pattern:".*>Domino ([0-9.]+) Administrator Help<.*", replace:"Lotus-Domino/\1", string:r_from_webroot);

       if (r_from_webroot == v_from_webroot)
         v_from_webroot = NULL;
     }
   }

   # Go ahead and attempt SMTP in case it can
   # provide more detail than '/' web request
   if(get_port_state(25))
   {
     soc = open_sock_tcp(25);
     if(soc)
     {
       r = recv_line(socket:soc, length:4096);
       close(soc);
       v = ereg_replace(pattern:".*(Lotus|IBM) Domino .?Release ([^)]*).*", replace:"Lotus-Domino/\2", string:r);

       if( v == r)
       {
         # Here we have nothing from normal .nsf method
         # and nothing from SMTP.
         # v_from_webroot will be NULL if there is nothing
         # from the '/' request, so return it ... no versions from anywhere.
         # v_from_webroot will contain a version if available
         # from the '/' request, so return it.
         return v_from_webroot;
       }
       else
       {
         if (max_index(split(v, sep:".")) >= max_index(split(v_from_webroot, sep:".")))
           return v;
         else
           return v_from_webroot;
       }
     }
     else
     {
       # Here there was nothing from .nsf method
       # and further, no socket to SMTP, so return
       # v_from_webroot. It will be either NULL or
       # will contain a rough version number
       return v_from_webroot;
     }
   }
   else
   {
     # Here there was nothing from .nsf method
     # and further, no SMTP port open, so return
     # v_from_webroot. It will be either NULL or
     # will contain a rough version number
     return v_from_webroot;
   }
 }
 else
  return v;
}

# This is the old function from http_func.inc: it may return embedded
# servers and closed ports
port = get_http_port(default:80);
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

# Allow some cheap optimization
if (get_kb_item("www/"+port+"/PHP") || can_host_php(port: port))
 set_kb_item(name:"www/PHP", value: TRUE);
if (get_kb_item("www/"+port+"/ASP") || can_host_asp(port: port))
 set_kb_item(name:"www/ASP", value: TRUE);

foreach k ( make_list("www/banner/"+port, "get_http", "www/alt-banner/"+port) )
{
  if ("/" >!< k)
    resultrecv = get_kb_banner(port: port, type: k);
  else
  resultrecv = get_kb_item(k);
  svrline = egrep(string: resultrecv, pattern:"^Server:", icase: 1);
  if (svrline) break;
  svrline = egrep(pattern:"^DAAP-Server:", string:resultrecv, icase: 1);
  if (svrline) break;
}

if (! svrline)
{
  soctcp80 = http_open_socket(port);
  if (! soctcp80) exit(1, "Connection refused on port "+port);

  data = http_get(item:"/", port:port);
  resultsend = send(socket:soctcp80, data:data);
  resultrecv = http_recv_headers2(socket:soctcp80);
  resbody = http_recv(socket:soctcp80);
  close(soctcp80);

  svrline = egrep(pattern:"^Server:", string:resultrecv, icase: 1);
  if (! svrline)
    svrline = egrep(pattern:"^DAAP-Server:", string:resultrecv, icase: 1);
  # nb: newer releases of WebSphere don't have a Server response header; 
  #     we'll add a fake one if there's otherwise no header and it looks 
  #     like it's WAS.
  if (!svrline && ':WASRemoteRuntimeVersion="' >< resbody) 
    svrline = "Server: WebSphere Application Server";
  # nnb: even newer releases of WebSphere don't have a WASRemoteRuntimeVersion
  #      SOAP-ENV Header;
  #      we'll now check for a few remaining header entries
  if (!svrline && ':JMXMessageVersion' >< resbody && ':JMXVersion' >< resbody)
    svrline = "Server: WebSphere Application Server";
}

svrline = chomp(svrline);

xpower = egrep(string: resultrecv, pattern: "^X-Powered-By:", icase: 1);

svr = ereg_replace(pattern:"^[A-Z-]*Server: *(.*)$", string:svrline, replace:"\1", icase: 1);
svr = chomp(svr);
if (strlen(svr) == 0) exit(0, "No Server or DAAP-Server header on port "+port+".");

report = "";

if("Apache" >< svr)
{
     if("Apache/" >< svr)report = report + svr + string("\n\nYou can set the directive 'ServerTokens Prod' to limit the information\nemanating from the server in its response headers.");
     else if ("Apache-Coyote/" >< svr) {
       proto = strstr(svr, "/") - "/";
       proto = chomp(proto);
       report = report + "Coyote HTTP/" + proto + " Connector";
     }
     else
     {
       svr2 = get_apache_version();
      if( svr2 != NULL  )
        {
	  report = report + svr2 + string("\n\nThe 'ServerTokens' directive is set to ProductOnly\n",
	  				"however we could determine that the version of the remote\n",
					"server by requesting a nonexistent page.\n");
	  svrline = string("Server: ", svr2, "\r\n");
	  replace_kb_item(name:string("www/real_banner/", port), value:svrline);
	  if(!get_kb_item("www/banner/" + port))
	  {
	    replace_kb_item(name:"www/banner/" + port, value:svrline);
	  }
       }
       else report = report + svr + string("\nand the 'ServerTokens' directive is ProductOnly\nApache does not offer a way to hide the server type.\n");
     }
    }else{
     if("Lotus-Domino" >< svr)
     {
      if(ereg(pattern:"Lotus-Domino/[1-9]\.[0-9]", string:svr) ) report = report + svr;
      else {
      	svr2 = get_domino_version();
	if( svr2 != NULL )
	{
	 report = report + svr2 + string("\n\nThe product version is hidden but we could determine it by\n",
	 				"requesting a nonexistent .nsf file, a default index file or connecting to port 25\n");
	 svrline = string("Server: ", svr2, "\r\n");
	 replace_kb_item(name:string("www/real_banner/", port), value:svrline);

	 if(!get_kb_item("www/banner/" + port))
	  {
	    replace_kb_item(name:"www/banner/" + port, value:svrline);
	  }
	}
	 else report = report + svr;
     }
     }
     else
     {
     report = report + svr;
     }
    }

    report = string (
		"The remote web server type is :\n\n",
		report
		);

    security_note(port:port, extra:report);

    #
    # put the name of the web server in the KB
    #
    if(ereg(pattern:"^Server:.*Domino", string:svrline))
    	set_kb_item(name:"www/domino", value:TRUE);

    if(ereg(pattern:"^Server:.*Apache", string:svrline))
    	set_kb_item(name:"www/apache", value:TRUE);

    if(ereg(pattern:"^Server:.*(Apache.* Tomcat|Apache-Coyote)/", string:svrline, icase:1))
    	set_kb_item(name:"www/tomcat", value:TRUE);

    if(ereg(pattern:"^Server:.*Microsoft", string:svrline))
    	set_kb_item(name:"www/iis", value:TRUE);

    if(ereg(pattern:"^Server:.*Zope", string:svrline))
       set_kb_item(name:"www/zope", value:TRUE);

    if(ereg(pattern:"^Server:.*CERN", string:svrline))
       set_kb_item(name:"www/cern", value:TRUE);

    if(ereg(pattern:"^Server:.*Zeus", string:svrline))
       set_kb_item(name:"www/zeus", value:TRUE);

     if(ereg(pattern:"^Server:.*WebSitePro", string:svrline))
       set_kb_item(name:"www/websitepro", value:TRUE);

    if(ereg(pattern:"^Server:.*NCSA", string:svrline))
    	set_kb_item(name:"www/ncsa", value:TRUE);

    if(ereg(pattern:"^Server:.*Netscape-Enterprise", string:svrline))
    	set_kb_item(name:"www/iplanet", value:TRUE);

    if(ereg(pattern:"^Server:.*Netscape-Administrator", string:svrline))
    	set_kb_item(name:"www/iplanet", value:TRUE);

    if (ereg(pattern:"^Server:.*PanWeb Server/", string:svrline))
      set_kb_item(name:"www/panweb", value:TRUE);

    if(ereg(pattern:"^Server:.*thttpd/", string:svrline))
	set_kb_item(name:"www/thttpd", value:TRUE);

    if(ereg(pattern:"^Server:.*lighttpd/", string:svrline))
	set_kb_item(name:"www/lighttpd", value:TRUE);

    if(ereg(pattern:"^Server:.*nginx/", string:svrline))
	set_kb_item(name:"www/nginx", value:TRUE);

    if(ereg(pattern:"^Server:.*WDaemon", string:svrline))
	set_kb_item(name:"www/wdaemon", value:TRUE);

    if(ereg(pattern:"^Server:.*SAMBAR", string:svrline))
	set_kb_item(name:"www/sambar", value:TRUE);

    if(ereg(pattern:"^Server:.*IBM[- _]HTTP[- _]Server", string:svrline))
	set_kb_item(name:"www/ibm-http", value:TRUE);

    if(ereg(pattern:"^Server:.*Alchemy", string:svrline))
	set_kb_item(name:"www/alchemy", value:TRUE);

    if(ereg(pattern:"^Server:.*Rapidsite/Apa", string:svrline))
	set_kb_item(name:"www/apache", value:TRUE);

     if(ereg(pattern:"^Server:.*Statistics Server", string:svrline))
	set_kb_item(name:"www/statistics-server", value:TRUE);

     if(ereg(pattern:"^Server:.*CommuniGatePro", string:svrline))
	set_kb_item(name:"www/communigatepro", value:TRUE);

     if(ereg(pattern:"^Server:.*Savant", string:svrline))
	set_kb_item(name:"www/savant", value:TRUE);

     if(ereg(pattern:"^Server:.*StWeb", string:svrline))
        set_kb_item(name:"www/stweb", value:TRUE);

     if(ereg(pattern:"^Server:.*StWeb", string:svrline))
        set_kb_item(name:"www/apache", value:TRUE);

     # All Oracle HTTP services.
     if (ereg(pattern:"^Server:.*Oracle.*Server", string:svrline))
       set_kb_item(name:"www/oracle", value:TRUE);

     # Only the Oracle HTTP Server.
     if (ereg(pattern:"^Server:.*Oracle HTTP Server", string:svrline))
     {
       set_kb_item(name:"www/OracleApache", value:TRUE);
       set_kb_item(name:"www/apache", value:TRUE);
     }

     if(ereg(pattern:"^Server:.*Stronghold", string:svrline))
     {
        set_kb_item(name:"www/stronghold", value:TRUE);
        set_kb_item(name:"www/apache", value:TRUE);
     }

     if(ereg(pattern:"^Server:.*WebSphere Application Server", string:svrline))
        set_kb_item(name:"www/WebSphere", value:TRUE);

     if(ereg(pattern:"^Server:.*MiniServ", string:svrline))
        set_kb_item(name:"www/miniserv", value:TRUE);

     if(ereg(pattern:"^Server:.*vqServer", string:svrline))
        set_kb_item(name:"www/vqserver", value:TRUE);

     if(ereg(pattern:"^Server:.*VisualRoute", string:svrline))
        set_kb_item(name:"www/visualroute", value:TRUE);

     if(ereg(pattern:"^Server:.*[Ss]quid", string:svrline))
        set_kb_item(name:"www/squid", value:TRUE);

     if(ereg(pattern:"^Server:.*OmniHTTPd", string:svrline))
        set_kb_item(name:"www/omnihttpd", value:TRUE);

     if(ereg(pattern:"^Server:.*linuxconf", string:svrline))
        set_kb_item(name:"www/linuxconf", value:TRUE);

     if(ereg(pattern:"^Server:.*CompaqHTTPServer", string:svrline))
        set_kb_item(name:"www/compaq", value:TRUE);

     if(ereg(pattern:"^Server:.*WebSTAR", string:svrline))
        set_kb_item(name:"www/webstar", value:TRUE);

     if(ereg(pattern:"^Server:.*AppleShareIP", string:svrline))
        set_kb_item(name:"www/appleshareip", value:TRUE);

     if(ereg(pattern:"^Server:.*Jigsaw", string:svrline))
        set_kb_item(name:"www/jigsaw", value:TRUE);

     if(ereg(pattern:"^Server:.*Resin", string:svrline))
        set_kb_item(name:"www/resin", value:TRUE);

     if(ereg(pattern:"^Server:.*AOLserver", string:svrline))
        set_kb_item(name:"www/aolserver", value:TRUE);

     if(ereg(pattern:"^Server:.*IdeaWebServer", string:svrline))
        set_kb_item(name:"www/ideawebserver", value:TRUE);

     if(ereg(pattern:"^Server:.*FileMakerPro", string:svrline))
        set_kb_item(name:"www/filemakerpro", value:TRUE);

     if(ereg(pattern:"^Server:.*NetWare-Enterprise-Web-Server", string:svrline))
        set_kb_item(name:"www/netware", value:TRUE);

     if(ereg(pattern:"^Server:.*Roxen", string:svrline))
        set_kb_item(name:"www/roxen", value:TRUE);

     if(ereg(pattern:"^Server:.*SimpleServer:WWW", string:svrline))
        set_kb_item(name:"www/simpleserver", value:TRUE);

     if(
       ereg(pattern:"^Server: RomPager", string:svrline) ||
       ereg(pattern:"^Server:.*Allegro-Software-RomPager", string:svrline)
     ) set_kb_item(name:"www/allegro", value:TRUE);

     if(ereg(pattern:"^Server:.*GoAhead-Webs", string:svrline))
        set_kb_item(name:"www/goahead", value:TRUE);

     if(ereg(pattern:"^Server:.*Xitami", string:svrline))
        set_kb_item(name:"www/xitami", value:TRUE);

     if(ereg(pattern:"^Server:.*EmWeb", string:svrline))
        set_kb_item(name:"www/emweb", value:TRUE);

     if(ereg(pattern:"^Server:.*Ipswitch-IMail", string:svrline))
        set_kb_item(name:"www/ipswitch-imail", value:TRUE);

     if(ereg(pattern:"^Server:.*Netscape-FastTrack", string:svrline))
        set_kb_item(name:"www/netscape-fasttrack", value:TRUE);

     if(ereg(pattern:"^Server:.*AkamaiGHost", string:svrline))
        set_kb_item(name:"www/akamaighost", value:TRUE);

     if(ereg(pattern:"^Server:.*[aA]libaba", string:svrline))
        set_kb_item(name:"www/alibaba", value:TRUE);

     if(ereg(pattern:"^Server:.*tigershark", string:svrline))
        set_kb_item(name:"www/tigershark", value:TRUE);

     if(ereg(pattern:"^Server:.*Netscape-Commerce", string:svrline))
        set_kb_item(name:"www/netscape-commerce", value:TRUE);

     if(ereg(pattern:"^Server:.*Oracle_Web_listener", string:svrline))
        set_kb_item(name:"www/oracle-web-listener", value:TRUE);

     if(ereg(pattern:"^Server:.*Caudium", string:svrline))
        set_kb_item(name:"www/caudium", value:TRUE);

     if(ereg(pattern:"^Server:.*Communique.*", string:svrline))
        set_kb_item(name:"www/communique", value:TRUE);

     if(ereg(pattern:"^Server:.*Cougar.*", string:svrline))
        set_kb_item(name:"www/cougar", value:TRUE);

     if(ereg(pattern:"^Server:.*FirstClass.*", string:svrline))
        set_kb_item(name:"www/firstclass", value:TRUE);

     if(ereg(pattern:"^Server:.*NetCache.*", string:svrline))
        set_kb_item(name:"www/netcache", value:TRUE);

     if(ereg(pattern:"^Server:.*AnWeb.*", string:svrline))
        set_kb_item(name:"www/anweb", value:TRUE);

     if(ereg(pattern:"^Server:.*Pi3Web.*", string:svrline))
        set_kb_item(name:"www/pi3web", value:TRUE);

     if(ereg(pattern:"^Server:.*TUX.*", string:svrline))
        set_kb_item(name:"www/tux", value:TRUE);

     if(ereg(pattern:"^Server:.*Abyss.*", string:svrline))
        set_kb_item(name:"www/abyss", value:TRUE);

     if(ereg(pattern:"^Server:.*BadBlue.*", string:svrline))
        set_kb_item(name:"www/badblue", value:TRUE);

     if(ereg(pattern:"^Server:.*WebServer 4 Everyone.*", string:svrline))
        set_kb_item(name:"www/webserver4everyone", value:TRUE);

     if(ereg(pattern:"^Server:.*KeyFocus Web Server.*", string:svrline))
        set_kb_item(name:"www/KFWebServer", value:TRUE);

     if(ereg(pattern:"^Server:.*Jetty.*", string:svrline))
        set_kb_item(name:"www/jetty", value:TRUE);

     if(ereg(pattern:"^Server:.*bkhttp/.*", string:svrline))
        set_kb_item(name:"www/BitKeeper", value:TRUE);

     if(ereg(pattern:"^Server:.*CUPS(/.*)?$", string:svrline))
        set_kb_item(name:"www/cups", value:TRUE);

     if(ereg(pattern:"^Server:.*Novell-HTTP-Server.*", string:svrline))
       	set_kb_item(name:"www/novell", value:TRUE);

     if(ereg(pattern:"^Server:.*theServer/.*", string:svrline))
       	set_kb_item(name:"www/theserver", value:TRUE);

     if(ereg(pattern:"^Server:.*WWW File Share.*", string:svrline))
        set_kb_item(name:"www/wwwfileshare", value:TRUE);

     if(ereg(pattern:"^Server:.*BCReport", string:svrline))
        set_kb_item(name:"www/BCReport", value:TRUE);

     if (ereg(pattern:"^Server: *eMule", string:svrline))
        set_kb_item(name:"www/eMule", value:TRUE);

     if (
        ereg(pattern:"^Server:.*CompaqHTTPServer/.+ HP System Management Homepage", string:svrline) ||
        ereg(pattern:"^Server:.*HP System Management Homepage/", string:svrline)
     ) set_kb_item(name:"www/hpsmh", value:TRUE);

     if (ereg(pattern:"^Server: *Xerver", string:svrline))
        set_kb_item(name:"www/xerver", value:TRUE);

     if (ereg(pattern:"^Server:.*IceWarp", string:svrline))
        set_kb_item(name:"www/icewarp", value:TRUE);

     if (ereg(pattern:"^Server:.*UPnP", string:svrline))
        set_kb_item(name:"www/upnp", value:TRUE);

     if (ereg(pattern:"Server:.*MagnoWare/", string:svrline))
        set_kb_item(name:"www/magnoware", value:TRUE);

     if (ereg(pattern:"Server:.*CherryPy/", string:svrline))
        set_kb_item(name:"www/cherrypy", value:TRUE);

     if (ereg(pattern:"Server:.*Wing FTP Server/", string:svrline))
        set_kb_item(name:"www/wingftp", value:TRUE);

    if (ereg(pattern:"Server:.*SmarterTools/", string:svrline))
        set_kb_item(name:"www/smartertools", value:TRUE);

    if (ereg(pattern:"Server:.*GroupWise GWIA ", string:svrline))
      set_kb_item(name:"www/groupwise-ia", value:TRUE);

    if (ereg(pattern:"Server: *PRTG/", string:svrline))
      set_kb_item(name:"www/prtg", value:TRUE);

    if (ereg(pattern:"Server: ATS/", string:svrline))
      set_kb_item(name:"www/apache_traffic_server", value:TRUE);

    if (ereg(pattern:"Server: *TornadoServer/", string:svrline))
      set_kb_item(name:"www/tornado", value:TRUE);

    if (ereg(pattern:"Server: *((Embedthis-(Appweb|http))|Mbedthis-Appweb)/", string:svrline))
      set_kb_item(name:"www/appweb", value:TRUE);

    if (ereg(pattern:"Server: BigFixHTTPServer/", string:svrline))
      set_kb_item(name:"www/BigFixHTTPServer", value:TRUE);

    if (ereg(pattern:"Server: KS_HTTP/", string:svrline))
      set_kb_item(name:"www/KS_HTTP", value:TRUE);

   #  if(!ereg(pattern:"^Server:.*", string:svrline))
   #     set_kb_item(name:"www/none", value:TRUE);

    if (ereg(pattern:"Server: 3Com/v", string:svrline))
      set_kb_item(name:"www/3com", value:TRUE);

    if (ereg(pattern:"Server: IPWEBS/", string:svrline))
      set_kb_item(name:"www/ipwebs", value:TRUE);

####
if (xpower)
{
  if ("JBoss" >< xpower) set_kb_item(name: 'www/jboss', value: TRUE);
}
