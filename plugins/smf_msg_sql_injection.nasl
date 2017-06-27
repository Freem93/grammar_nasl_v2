#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18553);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_bugtraq_id(14043);
  script_name(english:"Simple Machines Forum msg Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for msg parameter SQL injection vulnerability in Simple Machines Forum");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Simple Machines Forum (SMF), an open source
web forum application written in PHP.

The installed version of SMF on the remote host fails to properly
sanitize input to the 'msg' parameter before using it in SQL queries.
By exploiting this flaw, an attacker can affect database queries,
possibly disclosing sensitive data and launching attacks against the
underlying database." );
  # http://web.archive.org/web/20061010150733/http://www.gulftech.org/?node=research&article_id=00089-07032005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?876b7dde");
 script_set_attribute(attribute:"see_also", value:"http://www.simplemachines.org/community/index.php?topic=39395.0" );
 script_set_attribute(attribute:"solution", value:"Upgrade to SMF version 1.0.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/23");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:simple_machines:smf");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("smf_detect.nasl");
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

port = get_http_port(default:80);

install = get_install_from_kb(appname:'simple_machines_forum', port:port, exit_on_fail:TRUE);

url = install['dir'] + '/';

version = install['ver'];
ver = split(sep:'.', ver);

for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 1 && ver[1] == 0 && ver[2] < 5)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n URL     : ' + url +
      '\n Version : ' + version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The Simple Machines Forum install at ' + url + ' is not affected because version ' + version+' is installed.');
