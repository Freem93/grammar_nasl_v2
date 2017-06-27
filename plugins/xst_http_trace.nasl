#
# This script was written by Thomas Reinke <reinke@securityspace.com>
# Improvements re TRACK and RFP reference courtesy of <sullo@cirt.net>
# Improvements by rd - http_get() to get full HTTP/1.1 support,
# security_warning() instead of security_hole(), slight re-phrasing
# of the description
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
#   - added solution in the plugin output for JSAS9 (3/29/13)
#   - added CVE xref.
#   - title update (9/18/09)
#   - updated CVSS score (12/14/2015)

include("compat.inc");

if (description)
{
 script_id(11213);
 script_version("$Revision: 1.65 $");
 script_cvs_date("$Date: 2016/11/23 20:52:20 $");

 script_cve_id("CVE-2003-1567", "CVE-2004-2320", "CVE-2010-0386");
 script_bugtraq_id(9506, 9561, 11604, 33374, 37995);
 script_osvdb_id(877, 3726, 5648, 11408, 50485);
 script_xref(name:"CERT", value:"288308");
 script_xref(name:"CERT", value:"867593");

 script_name(english:"HTTP TRACE / TRACK Methods Allowed");
 script_summary(english:"Test for TRACE / TRACK Methods.");

 script_set_attribute(attribute:"synopsis", value:
"Debugging functions are enabled on the remote web server.");
 script_set_attribute(attribute:"description", value:
"The remote web server supports the TRACE and/or TRACK methods. TRACE
and TRACK are HTTP methods that are used to debug web server
connections.");
 script_set_attribute(attribute:"see_also", value:"http://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf");
 script_set_attribute(attribute:"see_also", value:"http://www.apacheweek.com/issues/03-01-24");
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1000718.1.html");
 script_set_attribute(attribute:"solution", value:
"Disable these methods. Refer to the plugin output for more information.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16, 200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 E-Soft Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

sol["apache"] = "
To disable these methods, add the following lines for each virtual
host in your configuration file :

    RewriteEngine on
    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
    RewriteRule .* - [F]

Alternatively, note that Apache versions 1.3.34, 2.0.55, and 2.2
support disabling the TRACE method natively via the 'TraceEnable'
directive.
";

sol["iis"] = "
Use the URLScan tool to deny HTTP TRACE requests or to permit only the
methods needed to meet site requirements and policy.
";

sol["SunONE"] = '
To disable this method, add the following to the default object
section in obj.conf :

    <Client method="TRACE">
     AuthTrans fn="set-variable"
     remove-headers="transfer-encoding"
     set-headers="content-length: -1"
     error="501"
    </Client>

If you are using Sun ONE Web Server releases 6.0 SP2 or below, compile
the NSAPI plugin located at :

http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F50603
';

sol["Sun_JSAS7"] = '
To disable this method, add the following to the top of the default
object in <server-instance>-obj.conf :

  <Client method="TRACE">
  AuthTrans fn="set-variable" remove-headers="transfer-encoding"
  set-headers="content-length: -1" error="501"
           </Client>

and restart the Application server.
';

# this fix also works for JSAS 8 (tested against 8.2) even though it's undocumented for that version.
# unfortunately version 8 doesn't explicitly report its version in the server header
sol["Sun_JSAS9"] = '
To disable this method, edit domain.xml, adding the "traceEnabled"
property (set to "false") to the end of the http-service element :

        <property name="traceEnabled" value="false"/>
      </http-service>

and restart the application server.  Refer to the JSAS 9 Administrator
Reference for more information :

http://docs.oracle.com/cd/E19501-01/819-3661/auto126/index.html
';

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0, 'Port ' + port + ' is not open.');

banner = get_http_banner(port:port);
if ( ! banner ) exit(1, 'Unable to get the web server banner on port ' + port + '.');

if ( egrep(pattern:"^Server:.*IIS", string:banner) ) report = sol["iis"];
else if ( egrep(pattern:"^Server:.*Apache", string:banner) ) report = sol["apache"];
else if ( egrep(pattern:"^Server.*SunONE", string:banner) ) report = sol["SunONE"];
else if ( egrep(pattern:"^Server.*Sun-Java-System-Application-Server/7", string:banner) ) report = sol["Sun_JSAS7"];
else if ( egrep(pattern:"^Server.*Sun Java System Application Server (Platform Edition )?9", string:banner) ) report = sol["Sun_JSAS9"];

file = "/Nessus"+rand() + ".html";	# Does not exist

    cmd1 = http_get(item: file, port:port);
    cmd2 = cmd1;
    
    cmd1 = ereg_replace(pattern:"GET /", string:cmd1, replace:"TRACE /");
    cmd2 = ereg_replace(pattern:"GET /", string:cmd2, replace:"TRACK /");

    ua = egrep(pattern:"^User-Agent", string:cmd1, icase:TRUE);
 
    reply = http_keepalive_send_recv(port:port, data:cmd1, bodyonly:FALSE);
    if ( reply == NULL ) exit(0, 'The host is not affected on port ' + port + '.');
    if ( ereg(pattern:"^HTTP/.* 200 ", string:reply) )
    {
     r = strstr(reply, '\r\n\r\n');
     if (! r ) r = strstr(reply, '\n\n');
     full_reply = reply;
     reply = r;
     if(egrep(pattern:"^TRACE "+file+" HTTP/1\.", string:reply))
     {
	if ( ua && tolower(ua) >!< tolower(reply) ) exit(0, 'The host is not affected on port ' + port + '.');
        report += string(
          '\n',
          "Nessus sent the following TRACE request : \n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          str_replace(find:'\r\n', replace:'\n', string:cmd1),
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          "\n",
          "and received the following response from the remote server :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          str_replace(find:'\r\n', replace:'\n', string:full_reply),
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
	security_warning(port:port, extra:report);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
     }
    }  

    reply = http_keepalive_send_recv(port:port, data:cmd2, bodyonly:FALSE);
    if ( ereg(pattern:"^HTTP/.* 200 ", string:reply) )
    {
     r = strstr(reply, '\r\n\r\n');
     if (! r ) r = strstr(reply, '\n\n');
     full_reply = reply;
     reply = r;
     if(egrep(pattern:"^TRACK "+file+" HTTP/1\.", string:reply))
     {
       if ( ua && tolower(ua) >!< tolower(reply) ) exit(0, 'The host is not affected on port ' + port + '.');

       report += string(
         '\n',
         "Nessus sent the following TRACK request : \n",
         "\n",
         crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
         str_replace(find:'\r\n', replace:'\n', string:cmd2),
         crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
         "\n",
         "and received the following response from the remote server :\n",
         "\n",
         crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
         str_replace(find:'\r\n', replace:'\n', string:full_reply),
         crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
       );
       security_warning(port:port, extra:report);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     }
   }

exit(0, 'The host is not affected on port ' + port + '.');
