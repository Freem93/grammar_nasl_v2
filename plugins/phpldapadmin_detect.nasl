#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43401);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"phpLDAPadmin Detection");
  script_summary(english:"Looks for traces of phpLDAPadmin");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a web-based LDAP client written in PHP.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running phpLDAPadmin, an open source web-based
LDAP client written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://phpldapadmin.sourceforge.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deon_george:phpldapadmin");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/pla", "/phpldapadmin", "/xampp/pla", "/xampp/phpldapadmin", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;
version = "unknown";

foreach dir (dirs)
{
    # Try to grab the index page
    res = http_send_recv3(port:port, method:"GET", item:dir+"/index.php", follow_redirect:FALSE, exit_on_fail:TRUE);

    if (
      res[0] =~ '^HTTP/1\\.[01] +302' &&
      '<a href="cmd.php?cmd=show_cache" onclick="return ajDISPLAY' >!< res[2] &&
      'title="phpLDAPadmin logo" alt="phpLDAPadmin logo"' >!< res[2]
    )
    {
      hdrs = parse_http_headers(status_line:res[0], headers:res[1]);

      if (!isnull(hdrs['location']) && ereg(pattern:".+/index.php",string:hdrs['location']))
      {
        loc = eregmatch(pattern:"(.+)/index.php",string:hdrs['location']);
        if (!isnull(loc[1]))
        {
          if (ereg(pattern:"^/.+",string:loc[1])) dir = dir + loc[1];
          else dir = dir + '/' + loc[1];
        }
        else dir = dir + '/htdocs';
      }
      else dir = dir + '/htdocs';

      res = http_send_recv3(port:port, method:"GET", item:dir+"/index.php", exit_on_fail:TRUE);
    }

    if (
      (
        '<a href="cmd.php?cmd=show_cache" onclick="return ajDISPLAY' >< res[2] ||
        'title="phpLDAPadmin logo" alt="phpLDAPadmin logo"' >< res[2]
      ) &&
      egrep(pattern:"<[tT][iI][tT][lL][eE]>phpLDAPadmin ",string:res[2])
    )
    {
      # Check if we can get the version...
      if (egrep(pattern:"<[tT][iI][tT][lL][eE]>phpLDAPadmin *\([0-9.]+\)",string:res[2]))
      {
        version = strstr(res[2],">phpLDAPadmin ") - ">phpLDAPadmin (";
        version = version - strstr(version,") - </");
      }

      # If we can't get the version, look at the footer...
      if (
        !ereg(pattern:"^[0-9.]+$",string:version) &&
        egrep(pattern:'"foot"><td colspan=3>[0-9.]+</td></tr></table></body></html>',string:res[2])
      )
      {
        version = strstr(res[2],'<tr class="foot"><td colspan=3>') - '<tr class="foot"><td colspan=3>';
        version = version - strstr(version,'</td></tr></table></body></html>') ;
      }

      if (!ereg(pattern:"^[0-9.]+$",string:version)) version = "unknown";

      installs = add_install(
        appname  : "phpLDAPadmin",
        installs : installs,
        port     : port,
        dir      : dir,
        ver      : version
      );

      if(!thorough_tests) break;
    }
}
if (isnull(installs)) exit(0, "phpLDAPadmin was not detected on the web server on port "+port+".");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : "/index.php",
    display_name : "phpLDAPadmin"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
