#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90422);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/09/26 14:31:38 $");

  script_cve_id("CVE-2016-0888");
  script_bugtraq_id(85808);
  script_osvdb_id(136419);

  script_name(english:"EMC Documentum D2 < 4.6 Insufficient ACL Remote Object Manipulation (ESA-2016-034)");
  script_summary(english:"Checks the version of Documentum D2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version EMC Documentum D2 that is prior
to 4.6. It is, therefore, affected by a security bypass vulnerability
due to a failure to set secure access control lists (ACLs) for D2
configuration objects. An authenticated, remote attacker can exploit
this to modify or delete D2 objects.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Apr/att-20/ESA-2016-034.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Documentum D2 version 4.6 later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_d2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("emc_documentum_d2_detect.nbin");
  script_require_keys("installed_sw/EMC Documentum D2");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "EMC Documentum D2";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8080);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
url = build_url(port:port, qs:install['path']);
version = install['version'];
display_version = install['display_version'];
fix_display = FALSE;

if(version =~ "^4\.[1-5]\." || version =~ "^3\.")
  fix_display = "4.6.0000 (Any Build)";
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, display_version);

order  = make_list("URL", "Version", "Fixed version");
report = make_array(
  order[0], build_url(port:port, qs:install['path']),
  order[1], install['display_version'],
  order[2], fix_display
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
