#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56979);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/24 18:11:56 $");

  script_name(english:"Oracle WebLogic Detection");
  script_summary(english:"Checks for presence of Oracle WebLogic.");

  script_set_attribute(attribute:"synopsis", value:
"Oracle WebLogic is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Oracle (formerly BEA) WebLogic, a Java EE application server, is
running on the remote web server.");
  # http://www.oracle.com/technetwork/middleware/weblogic/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99924a19");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80, 7001);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("audit.inc"); 
include("t3.inc");

appname = "WebLogic";
port = get_http_port(default: 7001);
banner = get_http_banner(port: port);
if (isnull(banner)) audit(AUDIT_NO_BANNER, port);

function parse_cr_patches(server_string) 
{
  local_var cr_list;
  local_var cur_cr;
  local_var parsing_cr;
  local_var i;
  local_var cur_char;

  cr_list = make_list();
  parsing_cr = FALSE;
  cur_cr = '';

  for(i=0; i<strlen(server_string); i++) 
  {
    if (parsing_cr) 
    {
      cur_char = substr(server_string, i, i);
      if (cur_char == ' ' || cur_char == ',')
      {
        cr_list = make_list(cr_list, cur_cr);
        parsing_cr = FALSE;
      }
      else
      {
         if (cur_char =~ "[CR0-9]")
           cur_cr += cur_char;
         else parsing_cr = FALSE;
      }
    }
    else 
    {
      if (substr(server_string, i, i+3) =~ " CR[0-9]") {
        cur_cr = '';
        parsing_cr = TRUE;
      }
    }
  }

  return cr_list;
}

# Parses the old version of the Weblogic HTTP server field.
# Example server strings in header:
# Server: WebLogic Server 9.2 Fri Jun 23 20:47:26 EDT 2006 783464
# Server: WebLogic WebLogic Server 7.0 SP2  Sun Jan 26 23:09:32 PST 2003 234192
# Server: WebLogic Server 8.1 Temporary Patch for CR335437, CR341097 Wed Sep 05 17:29:52 PDT 2007
# Server: WebLogic Server 9.2 MP2 Mon Jun 25 01:32:01 EDT 2007 952826
# Server: WebLogic Server 10.0 MP1 Thu Oct 18 20:17:44 EDT 2007 1005184
# @param server_name the server field from the HTTP header
# @return a string describing the server if found
function old_style_banner(server_name)
{
  local_var info = 'URL : ' + build_url(port:port, qs:"/") + '\n';
  set_kb_item(name:"www/weblogic/" + port + "/source", value: server_name);

  local_var pattern = "^Server:.*WebLogic Server ([0-9]+\.[0-9]+)[0-9\.]*( SP[0-9]+ | MP[0-9]+ )?";
  local_var item = eregmatch(pattern: pattern, string: server_name);
  if (isnull(item)) audit(AUDIT_RESP_BAD, port);

  local_var version_number = item[1];
  info += 'Version : ' + version_number + '\n';
  set_kb_item(name:"www/weblogic/" + port + "/version", value:version_number);

  if (max_index(item) > 2)
  {
    local_var service_pack = ereg_replace(pattern:" (SP[0-9]+|MP[0-9]+) ", replace:"\1", string:item[2]);
    set_kb_item(name:"www/weblogic/" + port + "/service_pack", value:service_pack);
    info += 'Service / Maintenance Pack : ' + service_pack + '\n';
  }

  # Parse any critical patches that have been applied
  local_var patches = parse_cr_patches(server_string:server_name);
  if (max_index(patches) > 0) info += 'Critical patches applied : \n';

  local_var patch;
  foreach patch (patches)
  {
    set_kb_item(name:"www/weblogic/" + port + "/cr_patches/" + patch, value:TRUE);
    info += '  ' + patch + '\n';
  }
  return info;
}

# Tries to connect to the web admin login to determine if the server
# is WebLogic.
# @return a string describing the server if found
function get_web_console()
{
  local_var req = http_get(item: "/console/login/LoginForm.jsp", port: port);
  local_var sock = http_open_socket(port);
  if (!sock) audit(AUDIT_SOCK_FAIL, port);

  send(socket: sock, data: req);
  local_var res = http_recv(socket: sock);
  http_close_socket(sock);

  local_var info = '';
  if (strlen(res) && ("<title>Oracle WebLogic Server" >< res ||
    "<TITLE>BEA WebLogic Server" >< res))
  {
    info = 'URL : ' + build_url(port:port, qs:"/");

    # attempt to get the version from the login page (not availabe for BEA)
    local_var version = eregmatch(pattern: "WebLogic Server Version: ((?:\d+\.?){3,5})", string: res);
    if (version)
    {
      info += '\nVersion : ' + version[1];
      set_kb_item(name:"www/weblogic/" + port + "/version", value: version[1]);
    }
  }
  return info;
}

# Tries to connect through the HTTP port using the t3 protocol to determine
# if the server is WebLogic.
# @return a string describing the server if found
function get_t3_connection()
{
  local_var info = '';
  local_var sock = open_sock_tcp(port);
  if (!sock) audit(AUDIT_SOCK_FAIL, port);

  local_var version = t3_connect(sock:sock);
  close(sock);

  if (version)
  {
    info = 'URL : ' + build_url(port:port, qs:"/") + '\n';
    info += 'Version : ' + version;

    set_kb_item(name:"www/weblogic/" + port + "/version", value: version);
  }
  return info;
}

info = '';
server_name = egrep(pattern: "^Server:.*WebLogic.*", string: banner);
if (server_name)
{
  if (server_name =~ "^WL-Result:.*UNAVAIL.*")
  {
    info +=
      '\n' + 'While the remote server can be fingerprinted as WebLogic, the service' +
      '\n' + 'is currently unavailable, probably because of a connection limit with' +
      '\n' + 'licensing.\n';
  }
  else info = old_style_banner(server_name: server_name);
}
else
{
  info = get_web_console();
  if (info == '') info = get_t3_connection();
}

if (info == '') audit(AUDIT_NOT_INST, appname);
else
{
  set_kb_item(name:"www/weblogic", value: TRUE);
  set_kb_item(name:"www/weblogic/" + port + "/installed", value: TRUE);
}

if (report_verbosity > 0) security_note(port:port, extra:info);
else security_note(port);
