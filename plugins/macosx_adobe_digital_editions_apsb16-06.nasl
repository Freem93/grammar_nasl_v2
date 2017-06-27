#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89782);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2016-0954");
  script_bugtraq_id(84214);
  script_osvdb_id(135503);

  script_name(english:"Adobe Digital Editions < 4.5.1 RCE (APSB16-06) (Mac OS X)");
  script_summary(english:"Checks version of Adobe Digital Editions on Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Mac OS X
host is prior to 4.5.1. It is, therefore, affected by a remote code
execution vulnerability due to improper validation of user-supplied
input. An attacker can exploit this to corrupt memory, resulting in
the execution of arbitrary code.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb16-06.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ca0979c");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_digital_editions_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Digital Editions");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

app_name = "Adobe Digital Editions";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

ver_ui  = FALSE;
version = install['version'];
path    = install['path'];

if (!empty_or_null(install['display_version']))
  ver_ui  = install['display_version'];

fix = "4.5.1.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  items = make_array("Path", path,
                     "Installed version", version,
                     "Fixed version", "4.5.1 (" + fix + ")");
  if (ver_ui)
    items["Installed version"] = version + " (" + ver_ui + ")";

  order = make_list("Path", "Installed version", "Fixed version");

  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
