#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61431);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_bugtraq_id(54641);
  script_osvdb_id(84397);
  script_xref(name:"EDB-ID", value:"20037");

  script_name(english:"Atmail Email Server WebAdmin Control Panel dbconfig.ini Information Disclosure");
  script_summary(english:"Attempts to obtain the database configuration file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Atmail Webmail that fails to
properly restrict access to its database configuration file. 

A remote, unauthenticated attacker could obtain database connection
information and then leverage this data to assist in further attacks.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/atmail_webmail");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'atmail_webmail', port:port, exit_on_fail:TRUE);
dir = install["dir"];
install_loc = build_url(port:port, qs:dir + "/");

url = dir + '/config/dbconfig.ini';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  'database.params.password' >< res[2] &&
  'database.params.host'     >< res[2]
)
{
  if (report_verbosity > 0)
  {
    trailer = NULL;
    if (report_verbosity > 1)
    {
      db_config_data = '';
      foreach line (split(res[2]))
      {
        if (
          'database.params.host'     >< line ||
          'database.params.username' >< line ||
          'database.params.dbname'   >< line ||
          line =~ "^\["
        ) db_config_data += line;

        # mask pwd
        if ('database.params.password' >< line)
        {
          pwd_matches = eregmatch(pattern:'^(database\\.params\\.password[^"]+")(.*)"$', string:line);
          if (!isnull(pwd_matches)) pwd = pwd_matches[2];
          else continue;

          len = strlen(pwd);
          masked_pwd = substr(pwd, 0,0) + crap(data:'*', length: len - 2) + substr(pwd, len - 1, len -1);
          db_config_data += pwd_matches[1] + masked_pwd + '"\n';
        }
      }

      db_config_data =
        '\n' + 'This produced the following output : ' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + db_config_data +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

      trailer = db_config_data;
    }

    report = get_vuln_report(port:port, items:url, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_loc);
