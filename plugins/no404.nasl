#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# - rewritten in parts by H D Moore <hdmoore@digitaldefense.net>
#


include("compat.inc");

if(description)
{
 script_id(10386);
 script_version ("$Revision: 1.98 $");

 script_name(english:"Web Server No 404 Error Code Check");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server does not return 404 error codes." );
 script_set_attribute(attribute:"description", value:
"The remote web server is configured such that it does not return '404
Not Found' error codes when a nonexistent file is requested, perhaps
returning instead a site map, search page or authentication page.

Nessus has enabled some counter measures for this.  However, they
might be insufficient.  If a great number of security holes are
produced for this port, they might not all be accurate." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/28");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks if the remote web server issues 404 errors");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 RD / H D Moore");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_login.nasl", "webmirror.nasl", "waf_detection.nbin", "broken_web_server.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

function check(url, port)
{
    local_var req, result;

    req = http_get(item:url, port:port);
    result = http_keepalive_send_recv(data:req, port:port);
    if (isnull(result)) exit(1, "The web server on port "+port+" failed to respond.");
    return(result);
}

global_var	errmsg;

function find_err_msg(buffer)
{
    local_var cmsg, cpat;

    for (cmsg = 0; ! isnull(errmsg[cmsg]); cmsg ++)
    {
        cpat = errmsg[cmsg];
        if (egrep(pattern:cpat, string:buffer, icase:TRUE))
        {
            debug_print("no404 - '",cpat, "' found in '", buffer, "'\n");
            return(cpat);
        }
    }

    return NULL;
}

# build list of test urls

basename="404";
while ("404" >< basename) basename= "/" + rand_str(length:12);

i = 0;
foreach d (make_list("", "/cgi-bin", "/scripts"))
  foreach e (make_list("html", "cgi", "sh", "pl", "inc", "shtml", "asp", "php",
    "php3", "cfm" ) )
    badurl[i++] = strcat(d, basename, ".", e);

i = 0;
errmsg[i++] = "not found";
errmsg[i++] = "404";
errmsg[i++] = "error has occurred";
errmsg[i++] = "FireWall-1 message";
errmsg[i++] = "Reload acp_userinfo database";
errmsg[i++] = "IMail Server Web Messaging";
errmsg[i++] = "HP Web JetAdmin";
errmsg[i++] = "Error processing SSI file";
errmsg[i++] = "ExtendNet DX Configuration";
errmsg[i++] = "Unable to complete your request due to added security features";
errmsg[i++] = "Client Authentication Remote Service</font>";
errmsg[i++] = "Bad Request";
errmsg[i++] = "<form action=/session_login.cgi";	# webmin
errmsg[i++] = "Webmin server";
errmsg[i++] = "Management Console";	
errmsg[i++] = "TYPE=password";	# As in "<input type=password>"
errmsg[i++] = "The userid or password that was specified is not valid.";  # Tivoli server administrator   
errmsg[i++] = "Access Failed";
errmsg[i++] = "Please identify yourself:";
errmsg[i++] = "forcelogon.htm";
errmsg[i++] = "encountered an error while publishing this resource";
errmsg[i++] = "No website is configured at this address";
errmsg[i++] = 'name=qt id="search" size=40 value=" "';
errmsg[i++] = "PHP Fatal error:  Unable to open";
errmsg[i++] = "RSA SecurID User Name Request";
errmsg[i++] = "Error Occurred While Processing Request";
errmsg[i++] = "Web access denied";
errmsg[i++] = "Error Page";
errmsg[i++] = "The page you requested doesn't exist";
errmsg[i++] = "TYPE='password'";
errmsg[i++] = 'TYPE="password"';
errmsg[i++] = "This version of Compaq's management software has added";

global_var port, then;

function my_exit()
{
 local_var now, report;

 now = unixtime(); 
 if ( now - then > 60 && ! thorough_tests )
 {
  report = "
The remote web server is very slow - it took " + int(now - then) + "
seconds to execute the plugin no404.nasl (it usually only takes a few
seconds).

In order to keep the scan total time to a reasonable amount, the
remote web server has not been tested.

If you want to test the remote server, either fix it to have it reply
to Nessus' requests in a reasonable amount of time, or enable the
'Perform thorough tests' setting.";

  security_note(port:port, extra:report);
  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
  set_kb_item(name: "Services/www/" +port+ "/broken/reason", value: "The web server is much too slow");
 }
 exit(0);
}


port = get_http_port(default:80);

if(!get_port_state(port)) exit(1, "Port "+port+" is closed.");

found = string("www/no404/", port);

then = unixtime();

for (c = 0; badurl[c]; c = c + 1)
{
    url = badurl[c];
    
    debug_print(level: 2, "no404 - Checking URL ", url, " on port ", port, "\n");
    ret = check(url:url, port:port);
  
	# WebMin's miniserv and CompaqDiag behave strangely
	if ( egrep(pattern:"^Server: MiniServ/", string:ret) )
	{
	  set_kb_item(name:found, value:"HTTP");
          security_note(port:port, extra: '\nThis is MiniServ. CGI scanning will be disabled\n');
	  exit(0);
	}

	# MailEnable-HTTP does not handle connections fast enough
	if ( egrep(pattern:"^Server: MailEnable-HTTP/", string:ret) )
	{
	  set_kb_item(name:found, value:"HTTP");
	  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
	  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
	  set_kb_item(name: "Services/www/" +port+ "/broken/reason", value:
	  	"MailEnable-HTTP does not handle connections fast enough");
          security_note(port:port, extra: '\nMailEnable-HTTP does not handle connections fast enough\nTests have been disabled\n');
	  exit(0);
	}

	if ( egrep(pattern:"^Server: CompaqHTTPServer/", string:ret) )
	{
	  set_kb_item(name:found, value:"HTTP");
	  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
	  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
	  set_kb_item(name: "Services/www/" +port+ "/broken/reason", value:
	  	"The web server is CompaqHTTPServer");
	  security_note(port:port, extra: '\nCompaqHTTPServer cannot be tested.\nTests have been disabled\n');
	  exit(0);
	}

	# This is not a web server
	if ( egrep(pattern:"^DAAP-Server: ", string:ret) )
	{
	  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
	  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
	  set_kb_item(name: "Services/www/" +port+ "/broken/reason", value:
	  	"This is not a real server");
          security_note(port:port, extra: '\nThis is not a real web server.\nTests have been disabled\n');
	  exit(0);
	}

        raw_http_line = egrep(pattern:"^HTTP/", string:ret);
        # check for a 200 OK
        if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:raw_http_line))
        {
             # look for common "not found": indications
             not_found = find_err_msg(buffer:ret);
             if (! isnull(not_found))
             {
                not_found = string(not_found);
                set_kb_item(name:found, value: not_found);
                security_note(port:port, extra: '\nThe following string will be used :\n'+not_found);
                debug_print("no404 - 200: Using string: ", not_found, "\n");
                my_exit();              
             } else {
                
                # try to match the title
                title = egrep(pattern:"<title", string:ret, icase:TRUE);
                if (title)
                {
                    title = ereg_replace(string:title, pattern:".*<title>(.*)</title>.*", replace:"\1", icase:TRUE);
                    if (title)
                    {
                        debug_print("no404 - using string from title tag: ", title, "\n");
			debug_print(ret);
                        set_kb_item(name:found, value:title);
                        security_note(port:port, extra: 'The following title tag will be used :\n'+title);
                        my_exit();
                    }
                }
                
                # try to match the body tag
                body = egrep(pattern:"<body", string:ret, icase:TRUE);
                if (body)
                {
                    body = ereg_replace(string:chomp(body), pattern:"<body(.*)>", replace:"\1", icase:TRUE);
                    if (body)
                    {
                        debug_print("no404 - using string from body tag: ", body, "\n");
                        set_kb_item(name:found, value:body);
                        security_note(port:port, extra: '\nThe following body tag will be used :\n'+body);
                        my_exit();
                    }
                }
                
                # get mad and give up
                debug_print(level: 2, "no404 - argh! could not find something to match against.\n");
                debug_print(level: 2, "no404 - [response]", ret, "\n");
		msg = "
Unfortunately, Nessus has been unable to find a way to recognize this
page so some CGI-related checks have been disabled.
";
		security_note(port: port, extra: msg);
		set_kb_item(name:found, value:"HTTP");
                my_exit();
                
             }
        }
        
        # check for a 302 Moved Temporarily or 301 Move Permanently
        three_oh_match = eregmatch(string:raw_http_line, pattern:"^HTTP/[0-9]\.[0-9] (30[12]) ");
        if ( ! isnull(three_oh_match ))
        {
          three_oh_code = three_oh_match[1]; 
          msg = 
            '\n' + 
            '\nCGI scanning will be disabled for this host because the host responds' +
            '\nto requests for non-existent URLs with HTTP code '+three_oh_code +
            '\nrather than 404. The requested URL was : ' +
            '\n' +
            '\n    ' + build_url(port:port, qs:url) +
            '\n';
          security_note(port: port, extra: msg);
          set_kb_item(name:found, value:"HTTP");
          my_exit();
        }
        
}

my_exit();


