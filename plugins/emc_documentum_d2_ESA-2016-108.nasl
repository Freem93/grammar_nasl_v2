#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93716);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2016-6644");
  script_bugtraq_id(92906);
  script_osvdb_id(144230);

  script_name(english:"EMC Documentum D2 4.5.x < 4.5 P15 / 4.6.x < 4.6 P03 r_object_id Handling Unauthenticated Document Disclosure (ESA-2016-108)");
  script_summary(english:"Checks the version of Documentum D2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC Documentum D2 that is
4.5.x prior to 4.5.0150 (4.5 patch 15) or 4.6.x prior to 4.6.0030 (4.6
patch 03). It is, therefore, affected by an information disclosure
vulnerability due to improper validation of the 'r_object_id'
identifier. An unauthenticated, remote attacker can exploit this to
bypass security mechanisms and access any document in the Docbase.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Sep/att-18/ESA-2016-108.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Documentum D2 version 4.5.0150 (4.5 patch 15) /
4.6.0030 (4.6 patch 03) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_d2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
fix = NULL;
fix_display = NULL;

if (version =~ "^4\.5\.")
{
  fix = "4.5.0150";
  fix_display = "4.5.0150 (4.5 P15)";
}
else if (version =~ "^4\.6\.")
{
  fix = "4.6.0030";
  fix_display = "4.6.0030 (4.6 P03)";
}

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order  = make_list("URL", "Version", "Fixed version");
  report = make_array(
    order[0], build_url(port:port, qs:install['path']),
    order[1], install['display_version'],
    order[2], fix_display
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, display_version);
