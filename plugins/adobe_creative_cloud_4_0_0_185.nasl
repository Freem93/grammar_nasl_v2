#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99366);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id(
    "CVE-2017-3006",
    "CVE-2017-3007"
  );
  script_bugtraq_id(
    97555,
    97558
  );
  script_osvdb_id(
    155276,
    155277
  );
  script_xref(name:"IAVA", value:"2017-A-0093");

  script_name(english:"Adobe Creative Cloud Desktop < 4.0.0.185 Multiple Vulnerabilities (APSB17-13)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote
Windows host is prior to 4.0.0.185. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified flaw exists in the installation process
    due to improper usage of resource permissions that
    allows an unauthenticated, remote attacker to have an
    unspecified impact. (CVE-2017-3006)

  - An information disclosure vulnerability exists due to
    using insecure directory search paths when locating
    resources. An unauthenticated, remote attacker can
    exploit this to disclose sensitive information, which
    potentially could be used to facilitate further remote
    code execution attacks. (CVE-2017-3007)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb17-13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf78aeb2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 4.0.0.185 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Adobe Creative Cloud");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Adobe Creative Cloud';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

# For Adobe products, we compare the highest affected product, rather
# than the "fixed" version, as there is an ambiguous gap between what
# is considered affected and the fix.
highest_affected = "3.9.5.353";
fix = "4.0.0.185";

if (ver_compare(ver:version, fix:highest_affected, strict:FALSE) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
