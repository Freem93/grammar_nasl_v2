#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72392);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/07 19:28:41 $");

  script_cve_id("CVE-2014-1671");
  script_bugtraq_id(61382, 65029);
  script_osvdb_id(
    95534,
    95535,
    95536,
    95537,
    95538,
    95539,
    95540,
    95541,
    95542,
    102242,
    102243,
    102244,
    102245
  );
  script_xref(name:"EDB-ID", value:"27039");

  script_name(english:"Dell KACE K1000 < 5.5 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks version of KACE");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for a system management appliance is affected by
multiple SQL injection vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for the version of the Dell KACE K1000 appliance on
the remote host is affected by multiple SQL injection vulnerabilities. 
The following parameters and scripts are affected :

  - The 'TYPE_ID' parameter of 'adminui/history_log.php'.

  - The 'ID' parameter of 'adminui/service.php',
    'adminui/software.php',
    'adminui/settings_network_scan.php', 'adminui/asset.php',
    'adminui/asset_type.php', 'adminui/metering.php',
    'adminui/mi.php', 'adminui/replshare.php',
    'adminui/kbot.php', '/userui/advisory_detail.php',
    and '/userui/ticket.php'.

  - The 'macAddress' and 'getKBot' parameters of
    '/service/kbot_service.php'.

  - The 'ORDER[]' parameter of '/userui/ticket_list.php'.

Note that Nessus has not tested for these issues, but instead has relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vulnerability-lab.com/get_content.php?id=832");
  # http://www.baesystemsdetica.com.au/Research/Advisories/Dell-KACE-K1000-SQL-Injection-%28DS-2014-001%29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e29997ea");
  script_set_attribute(attribute:"see_also", value:"http://www.kace.com/support/resources/kb/solutiondetail?sol=SOL119257");
  script_set_attribute(attribute:"solution", value:"Upgrade KACE to version 5.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:kace_k1000_systems_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("dell_kace_k1000_web_detect.nbin");
  script_require_keys("www/dell_kace_k1000");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80);
prod = "Dell KACE K1000";

install = get_install_from_kb(
  appname      : "dell_kace_k1000",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, prod, install_url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 5 || (ver[0] == 5 && ver[1] < 5))
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 5.5 or later\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, prod, install_url, version);
