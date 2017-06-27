#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10147);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2016/02/25 21:53:14 $");

 script_name(english:"Nessus Server Detection");
 script_summary(english:"Connects to port 1241.");

 script_set_attribute(attribute:"synopsis", value:
"A Nessus daemon is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"A Nessus daemon is listening on the remote port.");
 script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/products/nessus-vulnerability-scanner");
 script_set_attribute(attribute:"solution", value:
"Ensure that the remote Nessus installation has been authorized.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencies("find_service2.nasl", "pvs_proxy_detect.nasl", "http_version.nasl");
 script_require_ports("Services/unknown", 1241, "Services/www", 8834);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");
include("json.inc");

app = 'nessus';

function nessus_detect(port)
{
 local_var soc, r;

 soc = open_sock_tcp(port);
 if (!soc) audit(AUDIT_SOCK_FAIL, port);

 send(socket:soc, data:'< NTP/1.2 >\n');
 r = recv_line(socket:soc, length:4096);
 if ( '< NTP/1.2 >' >< r )
 {
   r = recv(socket:soc, length:7);
   close(soc);
   if ( "User : " >< r )
  {
   register_service(proto:app, port:port);
   security_note(port);
   exit(0);
  }
 }
 else close(soc);
}

# Nessus >= 4.2
port = get_http_port(default:8834, dont_exit:TRUE);

version = NULL;
install = NULL;
extra   = make_array();
feed    = NULL;
web     = NULL;
ui      = NULL;

if (!isnull(port))
{
  server_header = http_server_header(port:port);
  if ('NessusWWW' >< server_header)
  {
    res = http_send_recv3(method:"GET", item:'/server/properties', port:port);
    if (!isnull(res))
    {
      if ("Nessus" >< res[2])
      {
        # Response body should contain a json string
        json = json_read(res[2]);

        # Version 5 returns a string with the same hierarchy as the XML on the /feed page
        if (res[2] =~ '^{"reply"') data = json[0]['reply']['contents'];
        # Version 6 gets straight to the point
        else data = json[0];

        if (data['nessus_type'] !~ '^Nessus')
          exit(0, "Server did not respond with expected Nessus Feed information.");

        if ("SecurityCenter" >< data['nessus_type'])
          extra["Managed by"] = "SecurityCenter";

        feed    = data['feed'];
        version = data['server_version'];
        ui      = data['nessus_ui_version'];
        web     = data['web_server_version'];

        if (!isnull(feed))   extra["Nessus feed"] = feed;
        if (!isnull(web))    extra["Web server version"] = web;
        if (!isnull(ui))     extra["Nessus UI Version"] = ui;
        if (isnull(version) || version == '0.0.0') version = UNKNOWN_VER;

        install = register_install(
          app_name : app,
          version  : version,
          port     : port,
          path     : '/',
          webapp   : TRUE,
          extra    : extra);
      }
      else
      {
        res = NULL;
        res = http_send_recv3(method:"GET", item:'/feed', port:port);
        if (!isnull(res))
        {
          if ('<nessus_type>Nessus' >!< res[2])
            exit(0, "Server did not respond with expected Nessus Feed information.");

          if ('<feed>' >< res[2])
          {
            feed = strstr(res[2], '<feed>') - '<feed>';
            feed = feed - strstr(feed, '</feed>');
          }

          if ('<server_version>' >< res[2])
          {
            version = strstr(res[2], '<server_version>') - '<server_version>';
            version = version - strstr(version, '</server_version>');
          }

          if ('<web_server_version>' >< res[2])
          {
            web = strstr(res[2], '<web_server_version>') - '<web_server_version>';
            web = web - strstr(web, '</web_server_version>');
          }

          if ('<nessus_ui_version>' >< res[2])
          {
            ui = strstr(res[2], '<nessus_ui_version>') - '<nessus_ui_version>';
            ui = ui - strstr(ui, '</nessus_ui_version>');
          }

          if (!isnull(feed)) extra["Nessus Feed"] = feed;
          if (!isnull(web)) extra["Web Server Version"] = web;
          if (!isnull(ui)) extra["Nessus UI Version"] = ui;

          install = register_install(
            app_name : app,
            version  : version,
            port     : port,
            path     : '/',
            webapp   : TRUE,
            extra    : extra);
        }
      }
    }
  }
}

if (!isnull(install))
{
  report_installs(app_name:app, port:port);
  exit(0);
}

# Nessus < 4.2
if (thorough_tests)
{
  port = get_unknown_svc(1241);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (silent_service(port)) audit(AUDIT_SVC_SILENT, port);
}
else port = 1241;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (known_service(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);
nessus_detect(port:port);
