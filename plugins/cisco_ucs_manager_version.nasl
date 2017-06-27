#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69919);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/16 18:03:04 $");

  script_name(english:"Cisco Unified Computing System (UCS) Manager Version");
  script_summary(english:"Obtains the UCS Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based management tool is listening on the remote device.");
  script_set_attribute(attribute:"description", value:
"Cisco Unified Computing System (UCS) Manager software is listening on
remote Cisco device. It allows for the management of Cisco UCS
hardware and software components.");
  # http://www.cisco.com/c/en/us/products/servers-unified-computing/ucs-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52eaffdc");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

dir = '';
page = '/';
url = dir + page;

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>Cisco UCS Manager' >!< res &&
  '>Cisco Unified Computing System' >!< res &&
  '<p>UCS Manager requires Java' >!< res &&
  '<h1>Cisco UCS Manager' >!< res
) audit(AUDIT_WEB_APP_NOT_INST, 'Cisco UCS Manager', port);

version = NULL;
match = eregmatch(pattern:'<h1>Cisco UCS Manager - ([0-9][^<]+)</h1>', string:res);
if (isnull(match)) match = eregmatch(pattern:'<span class=[\'"]style5[\'"]>Cisco Unified Computing System Manager v([0-9][^< ]+) *<br>', string:res);
if (isnull(match)) match = eregmatch(pattern:'<p class="version">Version ([0-9][^<]+)</p>', string:res);
if (isnull(match)) match = eregmatch(pattern:'<span class="version pull-right">([0-9][^<]+)</span>', string:res);
if (!isnull(match)) version = match[1];                    # e.g., 2.1(2a)

install = add_install(
  appname:'cisco_ucs_manager',
  dir:dir,
  port:port,
  ver:version
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Cisco UCS Manager',
    installs:install,
    port:port,
    item:page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
