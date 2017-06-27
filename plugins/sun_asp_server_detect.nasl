#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33438);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/11/22 21:06:09 $");

  script_name(english:"Sun Java System ASP Server Detection");
  script_summary(english:"Requests a nonexistent ASP page");

 script_set_attribute(attribute:"synopsis", value:
"An application server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an ASP Server, part of Sun Java System Active
Server Pages or an older variant such as Chili!Soft ASP, which
provides a web server with ASP (Active Server Pages) functionality." );
 script_set_attribute(attribute:"see_also", value:"http://www.sun.com/software/chilisoft/" );
 script_set_attribute(attribute:"solution", value:
"Limit access to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/www", 5100, "Services/unknown", 5102);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(5102);
  if (!port) exit(0, "No unknown server.");
  if (silent_service(port)) exit(0, "Service on port "+port+" is silent."); 
}
else
{
  port = 5102;
  if (known_service(port:port)) exit(0, "Service on port "+port+" is known.");
}
if (!get_tcp_port_state(port)) exit(0, "port "+port+" is closed.");


# Make sure the ASP server is working.
foreach http_port (add_port_in_list(list:get_kb_list("Services/www"), port:5100))
{
  res = http_get_cache(item:"/index.asp", port:http_port);
  if ("This functionality has not been inplemented yet" >< res) break;
}


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(1, "Connection refused on port "+port+".");


# Function to read a response.
function asp_read()
{
  local_var buf, hdr, i, j, len, pkt, req, res;

  res = "";
  for (i=0; i<10; i++)
  {
    hdr = recv(socket:soc, length:32, min:32);
    if (strlen(hdr) < 32 || hdr !~ '^[0-9]+ *[0-9]+ *[0-9]\x00$')
    {
      # nb: something's wrong -- read what's left and bail.
      buf = recv(socket:soc, length:40000);
      res = string(res, hdr, buf);
      return res;
    }

    len = int(substr(hdr, 15, 29));
    if (len <= 32) return NULL;

    len -= 32;
    buf = recv(socket:soc, length:len, min:len);
    if (len != strlen(buf))
    {
      # nb: something's wrong -- read what's left and bail.
      res = string(res, hdr, buf);
      buf = recv(socket:soc, length:40000);
      res = string(res, buf);
      return res;
    }

    res = string(res, hdr, buf);

    if (i == 0 && hdr !~ "^0 +") break;
    else if (i)
    {
      if (hdr =~ "^600 ")
      {
        req = 
          asp_string(s:"0              ") +
          asp_string(s:"nimda") +
          asp_string(s:"5              ");
        req = 
          "600" + crap(data:" ", length:12) + 
          string(strlen(req)+32) + crap(data:" ", length:15-strlen(string(strlen(req)+32))) +
          "0" + mkbyte(0) + 
          req;
        send(socket:soc, data:req);
      }
      else if (hdr !~ "^60[34] ") break;
      else 
      {
        req = asp_string(s:"1              ");
        req = 
          "0" + crap(data:" ", length:14) + 
          string(strlen(req)+32) + crap(data:" ", length:15-strlen(string(strlen(req)+32))) +
          "0" + mkbyte(0) + 
          req;
        send(socket:soc, data:req);
      }
    }
  }

  return res;
}

# Function to format a string for sending to the ASP server.
function asp_string(s)
{
  return string(strlen(s)) + crap(data:" ", length:14-strlen(string(strlen(s)))) + s + mkbyte(0);
}


# Initialize some variables.
cookie = "";
cwd = "/opt/nessus";
file = "/opt/nessus/"+SCRIPT_NAME;
group = "nobody";
method = "GET";
query_string = "";
url = "/"+SCRIPT_NAME;
user = "nobody";


# Issue a request for an invalid "ASP" page.
req = 
  asp_string(s:"135218572      ") +
  asp_string(s:"65538          ") +
  asp_string(s:user+"/"+group) +
  asp_string(s:method) +
  asp_string(s:query_string) +
  asp_string(s:url) +
  asp_string(s:file) +
  asp_string(s:cookie) +
  asp_string(s:"") +
  asp_string(s:"") +
  asp_string(s:"0              ") +
  asp_string(s:"") +
  asp_string(s:"") +
  asp_string(s:"/") +
  asp_string(s:cwd) +
  asp_string(s:"0              ");
req = 
  "606" + crap(data:" ", length:12) + 
  string(strlen(req)+32) + crap(data:" ", length:15-strlen(string(strlen(req)+32))) +
  "1" + mkbyte(0) + 
  req;
send(socket:soc, data:req);
res = asp_read();
close(soc);


# If the response looks right...
if (
  (
    '6             200 OK\x00' >< res ||
    '17            404 404 Not Found\x00' >< res
  )
)
{
  # Register and report the service.
  register_service(port:port, proto:"casp5102");
  security_note(port);
}
