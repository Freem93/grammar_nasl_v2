#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11462);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/09/22 17:06:55 $");

 script_name(english:"Bugzilla Software Detection");
 script_summary(english:"Checks for the presence of Bugzilla");

 script_set_attribute(attribute:"synopsis", value:"A bug tracker is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting Bugzilla, a web application for bug
tracking and managing software development.");
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Bugzilla';
port = get_http_port(default:80);
installed = FALSE;

if (thorough_tests) dirs = list_uniq(make_list("/bugs", "/bugzilla", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  version = NULL;
  url = dir + '/query.cgi';

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if  (
    (
      '<title>Find a Specific Bug</title>' >< res[2] &&
      'name="bug_status" id="bug_status"' >< res[2] &&
      'name="product" id="product"' >< res[2]
    ) ||
    (
      '<title>Search for bugs</title>' >< res[2] &&
      '<!-- 1.0@bugzilla.org -->'  >< res[2]
    ) ||
    (
      '<title>Log in to Bugzilla</title>' >< res[2] &&
      (
        'YAHOO.namespace(\'bugzilla\');' >< res[2] ||
        '<span>This is Bugzilla</span>' >< res[2]
      )
    ) ||
    (
      'id="Bugzilla_login" name="Bugzilla_login"' >< res[2] &&
      'id="Bugzilla_password" name="Bugzilla_password"' >< res[2]
    )||
    (
      '>Bugzilla &ndash; Simple Search</' >< res[2] &&
      '<input id="Bugzilla_login_top"' >< res[2]
    )
  )
  {
    pat = '(Bugzilla |class="header_addl_info">|<span>)[Vv]ersion ([0-9][^<]+)<?';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[2];
          break;
        }
      }
    }

    # Try the XMLRPC interface.
    if (!version)
    {
      url = dir + '/xmlrpc.cgi';
      xml = '<?xml version="1.0" encoding="UTF-8"?><methodCall>' +
            '<methodName>Bugzilla.version</methodName><params /></methodCall>';

      res = http_send_recv3( method:"POST", item:url, port:port,
                             add_headers: make_array( "Content-Type", "text/xml",
                                                      "Content-Length", strlen(xml) ),
                             data: xml, exit_on_fail:TRUE);

      if( "<methodResponse><params><param><value><struct><member><name>version</name><value><string>" >< res[2] )
        version = ereg_replace(pattern:".*<name>version</name><value><string>([0-9][^<]+)</string>.*",
                            string:res[2], replace:"\1", icase:FALSE);
      if (version) set_kb_item(name:string("www/", port, "/bugzilla/xmlrpc_enabled"), value:TRUE);
    }

    # Try to read the version from the main index page.
    if (!version)
    {
      url = dir + '/';
      res2 = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

      pat = '(Bugzilla |class="header_addl_info">|<span>)[Vv]ersion ([0-9][^<]+)<?';
      matches = egrep(pattern:pat, string:res2);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            version = item[2];
            break;
          }
        }
      }
    }

    register_install(
      app_name : app,
      path     : dir,
      version  : version,
      port     : port,
      cpe      : "cpe:/a:mozilla:bugzilla",
      webapp   : TRUE
    );

    installed = TRUE;

    if (!thorough_tests) break;
  }
}

if (!installed) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
