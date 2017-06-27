#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43163);
  script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_bugtraq_id(37208, 37263);
  script_osvdb_id(60876, 60877, 60879);
  script_xref(name:"Secunia", value:"37598");
  script_xref(name:"Secunia", value:"37680");

  script_name(english:"Invision Power Board < 3.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Invision Power Board.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Invision Power Board earlier
than 3.0.5.  Such versions are potentially affected by multiple
vulnerabilities :

  - A local-file include vulnerability affects the 'section'
    parameter sent to the 'forum/index.php' script.

  - A SQL injection vulnerability affects the 'starter' and
    'state' parameters of the
    'admin/applications/forum/modules_public/moderate/moderate.php'
    script.

  - A cross-site scripting vulnerability is caused by
    incorrect handling of '.txt' file attachments."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Dec/139");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2009/Dec/105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1407869f"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Invision Power Board 3.0.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:invisionpower:invision_power_board");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");

install = get_install_from_kb(appname:'invision_power_board', port:port);
if (isnull(install)) exit(0, "Invision Power Board has not been detected on the web server on port "+port+".");

ver = split(sep:'.', install['ver'], keep:FALSE);

for (i=0;i<max_index(ver);i++)
  ver[i] = int(ver[i]);

if (ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 5)
)
{
  if(report_verbosity > 0)
  {
    report = get_vuln_report(
      header:'Nessus found the following vulnerable Invision Power Board install',
      items:install['dir'],
      port:port
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else exit(0, 'The Invision Power Board install at '+build_url(qs:install['dir'], port:port)+' is not affected.');
