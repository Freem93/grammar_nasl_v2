# nnposter
# GPL

# Changes by Tenable:
# - Revised plugin title (3/30/2009)

include("compat.inc");

if (description)
    {
    script_id(25569);
    script_version ("$Revision: 1.6 $");

    script_name(english:"Packeteer Web Management Interface Version Detection");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to determine the version of the remote web application." );
 script_set_attribute(attribute:"description", value:
"Nessus was able to determine the software version of the Packeteer web
management interface running on the remote host." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_cvs_date("$Date: 2011/02/26 23:44:38 $");
 script_end_attributes();

    summary["english"]="Tests for Packeteer web interface version";
    script_summary(english:summary["english"]);

    family["english"]="CGI abuses";
    script_family(english:family["english"]);

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (c) 2007-2011 nnposter");
    script_dependencies("packeteer_web_login.nasl");
    script_require_keys("www/packeteer");
    script_require_ports("Services/www",80);
    exit(0);
    }

# Notes:
# - Info page is bigger than 8K and PacketShaper does not use Content-Length.
#   The script uses custom http_send_recv_length() to retrieve the entire page.


include("http_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("www/packeteer");


function set_cookie (data,cookie)
{
local_var EOL,req;
EOL='\r\n';
req=ereg_replace(string:data,pattern:EOL+'Cookie:[^\r\n]+',replace:"");
req=ereg_replace(string:req,pattern:EOL+EOL,replace:EOL+cookie+EOL);
return req;
}


function http_send_recv_length (port,data,length)
{
local_var sock,resp;
sock=http_open_socket(port);
if (!sock) return NULL;
send(socket:sock,data:data);
resp=http_recv_length(socket:sock,bodylength:length);
http_close_socket(sock);
return resp;
}


function get_version (port,cookie)
{
local_var req,resp,match;
if (!port || !cookie) return NULL;
if (!get_tcp_port_state(port)) return NULL;
req=set_cookie(data:http_get(item:"/info.htm",port:port),cookie:cookie);
resp=http_send_recv_length(port:port,data:req,length:64000);
if (isnull(resp)) return NULL;
match=eregmatch(
        pattern:'makeState\\("Software(.nbsp.| )Version:", *"([0-9A-Za-z.]+)',
        string:resp);
return match[2];
}


port=get_http_port(default:80);
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is closed.");
product = get_kb_item_or_exit("www/"+port+"/packeteer");
get_kb_item_or_exit('/tmp/http/auth/'+port);

version=get_version(port:port,cookie:get_kb_item("/tmp/http/auth/"+port));
if (isnull(version))
 exit(0, "Packeteer's version cannot be extracted on port "+port+".");

replace_kb_item(name:"www/"+port+"/packeteer/version",value:version);
report = string(
  "\n",
  "Packeteer "+product+" web interface version is "+version
);
security_note(port:port,extra:report);
