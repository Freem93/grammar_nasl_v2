#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46739);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/03/25 23:33:24 $");

  script_name(english:"Apache Axis2 Detection");
  script_summary(english:"Checks for Apache Axis2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an open source web services engine.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Apache Axis2, an open source web services
engine.");
  script_set_attribute(attribute:"see_also", value:"https://axis.apache.org/axis2/java/core/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:axis2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port, exit_on_fail: TRUE);

dists = make_array();
services = make_array();
installs = NULL;
app = 'Axis2';

# We need separate checks if Axis is running on the internal web server or
# through a servlet container.
if ('Server: Simple-Server' >< banner)
{
  dir = '/axis2';
  url = dir +'/services/';

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if ('<title>Axis2: Services</title>' >< res[2])
  {
    # Determine the installed services
    pattern = '<a href="(.*)\\?wsdl">';
    matches = egrep(pattern:pattern, string:res[2], icase:FALSE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pattern, string:match);
        if (!isnull(item))
        {
          services[dir] += item[1] + ', ';
        }
      }
      if (", " >< services[dir]) services[dir] = substr(services[dir], 0, strlen(services[dir])-3);
    }

    # Determine the version from the Version service if it exists.
    if ('Version' >< services[dir])
    {
      res = http_send_recv3(method:"GET", item:dir+'/services/Version/getVersion', port:port, exit_on_fail:TRUE);

      if ('<ns:getVersionResponse' >< res[2])
      {
        if ('Hello I am Axis2 version service' >< res[2])
        {
          pattern = 'My version is ([0-9\\.]+)';
        }
        else pattern = '<ns:return>Hi - the Axis2 version is ([0-9\\.]+)';

        matches = egrep(pattern:pattern, string:res[2], icase:FALSE);
        if (matches)
        {
          foreach match (split(matches,  keep:FALSE))
          {
            item = eregmatch(pattern:pattern, string:match);
            if (!isnull(item))
            {
              version = item[1];
              break;
            }
          }
        }
      }
    }

    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:app,
      port:port
    );
    dists[dir] = 'Binary';
    set_kb_item(name:app+'/'+port+dir+'/dist', value:'binary');
    if ( !isnull(services[dir]) ) set_kb_item(name:app+'/'+port+dir+'/services', value:services[dir]);
  }
}
else
{
  # Axis2 will typically be at /axis2, but it is possible to change this
  # when running through a servlet container. '/dswsbobje' is used by
  # SAP BusinessObjects when used with Tomcat, and '/imcws' is used by
  # 3com's IMC network management tool.
  # CA Arcserve D2D uses /WebServiceImpl/axis2-admin
  dirs = list_uniq(make_list('/axis2', '/dswsbobje', '/imcws', '/WebServiceImpl/axis2-web', cgi_dirs()));

  foreach dir (dirs)
  {
    version = NULL;
    chk_version = FALSE;
    url = dir + '/';
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
    if (
      '<title>Axis 2 - Home</title>' >< res[2] &&
      res[2] =~ '<a href="(services/)?listServices">Services</a>'
    )
    {
      chk_version = TRUE;
    }
    else if ('<title>Axis 2 - Home</title>' >!< res[2])
    {
      url = dir + "/axis2-web/index.jsp";
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
      if (
        '<title>Axis 2 - Home</title>' >< res[2] &&
        res[2] =~ '<a href="(services/)?listServices">Services</a>'
      )
      {
        chk_version = TRUE;
      }
    }
    if (chk_version)
    {
      # Try to get a list of installed services
      pattern = '>Service Description : <font color="black">(.*)</f';

      # In CA ArcServe D2D, The basedir for the Services is /WebSerivceImpl
      # rather than /WebServiceImpl/axis2-web
      if (dir == '/WebServiceImpl/axis2-web') servicesdir = '/WebServiceImpl';
      else servicesdir = dir;

      res = http_send_recv3(method:"GET", item:servicesdir+'/services/listServices', port:port, exit_on_fail:TRUE);
     # Older versions of Axis2
     if (res[0] =~ "301|302")
     {
       res = http_send_recv3(method:"GET", item:servicesdir+'/listServices.jsp', port:port, exit_on_fail:TRUE);
       pattern = '<font color="blue"><a href=".*">(.*)</a></font><';
     }
      matches = egrep(pattern:pattern, string:res[2], icase:FALSE);
      if (!matches)
      {
        pattern = '<font color="blue"><a href=".*">(.*)</a></font><';
        matches = egrep(pattern:pattern, string:res[2], icase:FALSE);
      }
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pattern, string:match);
          if (!empty_or_null(item[1]))
          {
            services[dir] += item[1] + ', ';
          }
        }
        if (", " >< services[dir]) services[dir] = substr(services[dir], 0, strlen(services[dir])-3);
      }
      # Try to get the version info from the Version service if it exists.
      if (services[dir] =~ '(V|v)ersion')
      {
        if ('Version' >< services[dir])
        {
          ver_url = '/services/Version/getVersion';
        }
        else if ('version' >< services[dir])
        {
          ver_url = '/services/version/getVersion';
        }
        res = http_send_recv3(method:"GET", item:servicesdir + ver_url, port:port, exit_on_fail:TRUE);

        if (res[2] =~ '<(ns|ns1|res):getVersionResponse' || '<my:Version' >< res[2])
        {
          if ('Hello I am Axis2 version service' >< res[2])
          {
            pattern = 'My version is ([0-9\\.]+)';
          }
          else pattern = '<ns:return>Hi - the Axis2 version is ([0-9\\.]+)';

          matches = egrep(pattern:pattern, string:res[2], icase:FALSE);
          if (matches)
          {
            foreach match (split(matches, keep:FALSE))
            {
              item = eregmatch(pattern:pattern, string:match);
              if (!isnull(item))
              {
                version = item[1];
                break;
              }
            }
          }
        }
      }

      installs = add_install(
        installs:installs,
        ver:version,
        dir:dir,
        appname:app,
        port:port
      );
      dists[dir] = 'Servlet';
      set_kb_item(name:app+'/'+port+dir+'/dist', value:'servlet');
      if (!isnull(services[dir]) ) set_kb_item(name:app+'/'+port+dir+'/services', value:services[dir]);

      if (!thorough_tests) break;
    }
  }
}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);
if (report_verbosity > 0)
{
  n=0;
  info = "";
  foreach version (sort(keys(installs)))
  {
    info += '\n  Version      : ' + version + '\n';
    dirs = split(installs[version], sep:';', keep:FALSE);

    foreach dir (sort(dirs))
    {
      dir = base64_decode(str:dir);
      info += '  URL          : ' + build_url(port:port, qs:dir) + '\n';
      info += '  Distribution : ' + dists[dir] + '\n';
      info += '  Services     : ' + services[dir] + '\n';
      n++;
    }
  }
  report = '\nThe following instance';
  if (n == 1) report += ' of '+app+' was';
  else report += 's of '+app+' were';
  report += ' detected on the remote host :\n' + info;

  security_note(port:port, extra:report);
}
else security_note(port);
