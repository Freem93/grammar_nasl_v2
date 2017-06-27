#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93513);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 15:55:07 $");

  script_cve_id(
    "CVE-2016-4256",
    "CVE-2016-4257",
    "CVE-2016-4258",
    "CVE-2016-4259",
    "CVE-2016-4260",
    "CVE-2016-4261",
    "CVE-2016-4262",
    "CVE-2016-4263"
  );
  script_bugtraq_id(
    92925,
    92928
  );
  script_osvdb_id(
    144098,
    144099,
    144100,
    144101,
    144102,
    144103,
    144104,
    144105
  );

  script_name(english:"Adobe Digital Editions < 4.5.2 Multiple Vulnerabilities (APSB16-28)");
  script_summary(english:"Checks version of Adobe Digital Editions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Windows
host is prior to 4.5.2. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4256, CVE-2016-4257, CVE-2016-4258,
    CVE-2016-4259, CVE-2016-4260, CVE-2016-4261,
    CVE-2016-4262) 

  - A use-after-free error exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4263)");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb16-28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fee76481");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies('adobe_digital_editions_installed.nbin');
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');
include('smb_internals.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Digital Editions";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

ver_ui  = FALSE;
version = install['version'];
path    = install['path'];

if (!empty_or_null(install['display_version']))
  ver_ui  = install['display_version'];

fix = "4.5.2.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  port = kb_smb_transport();

  items = make_array("Path", path,
                     "Installed version", version,
                     "Fixed version", "4.5.2 (" + fix + ")");
  if (ver_ui)
    items["Installed version"] = version + " (" + ver_ui + ")";

  order = make_list("Path", "Installed version", "Fixed version");

  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
