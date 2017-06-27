#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46815);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/25 22:17:43 $");

  script_name(english:"MySQL Enterprise Monitor (MEM) Web Detection");
  script_summary(english:"Looks for the version of the MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based database monitoring application was detected on the remote
host.");
  script_set_attribute(attribute:"description", value:
"MySQL Enterprise Monitor (MEM), a distributed application for
monitoring multiple MySQL servers, is hosted on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.mysql.com/products/enterprise/monitor.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mysql:enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 18080, 18443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app  = "MySQL Enterprise Monitor";
port = get_http_port(default:18080);
installs = make_array();

# Version < 3.0.20
dir = '/';
res = http_send_recv3(
  method:"GET",
  item:'/',
  port:port,
  follow_redirect:1,
  exit_on_fail:FALSE
);

if (
  'MySQL Enterprise Dashboard</title>' >< res[2] &&
  '<td align="right">Monitor Instance</td>' >< res[2]
)
{
  pattern = '<td id="footerInfo">\\s+([0-9.]+)';
  matches = eregmatch(string:res[2], pattern:pattern, icase:TRUE);

  if (!empty_or_null(matches)) version = matches[1];

  installs = add_install(
    appname:app,
    port:port,
    dir:dir,
    ver:version
  );
}

# Version => 3.0.20 
if (max_index(keys(installs)) == 0)
{
  regexes = make_list();
  regexes[0] = make_list("This manual documents the MySQL Enterprise Monitor version");
  regexes[1] = make_list("<title>MySQL Enterprise Monitor ([0-9.]+)(?: Manual)?</title>");

  checks = make_array();
  checks["/Help.action"] = regexes;

  installs = find_install(
    appname : app,
    checks  : checks,
    dirs    : make_list(dir),
    port    : port,
    follow_redirect: 1
  );
}

# Version 3.3.x
if (max_index(keys(installs)) == 0)
{
  if (!isnull(res) &&
      "MySQL Enterprise Monitor" >< res[2] &&
      "Log In" >< res[2] &&
      "<title>" >< res[2]
  )
  {
    # grab CSRF token from head section
    title_start = stridx(res[2], "<title>");
    top = substr(res[2], 0, title_start);
    pat = '<meta\\s+name="_csrf"\\s+content="([a-zA-Z0-9\\-]+)"';
    match = eregmatch(pattern:pat, string:top);
    if (!isnull(match))
    {
      csrf = match[1];
      # log in

      user = get_kb_item("http/login");
      pass = get_kb_item("http/password");

      postdata = "_csrf="+csrf+"&j_username="+user+"&j_password="+pass;
      res = http_send_recv3(
        method:"POST",
        item:'/j_spring_security_check',
        port:port,
        data:postdata,
        add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
        follow_redirect:1,
        exit_on_fail:FALSE
      );

      if (!isnull(res) &&
          "200 OK" >< res[0] &&
          "MySQL Enterprise Monitor" >< res[2] &&
          "Manual</title>" >< res[2]
      )
      {
        # the manual is in the body
        title_end = stridx(res[2], "Manual</title>");
        top = substr(res[2], 0, title_end);
        pat = '<title>MySQL Enterprise Monitor\\s+([0-9\\.]+)\\s+M$';
        match = eregmatch(pattern:pat, string:top);
        if (!isnull(match))
        {
          version = match[1];
          installs = add_install(
            appname:app,
            port:port,
            dir:dir,
            ver:version
          );
        }
      }
    }
  }
}

if (max_index(keys(installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port,
    item         : dir
  );
  security_note(port:port, extra:report);
}
else security_note(port);
