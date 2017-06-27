#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91780);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/18 14:03:57 $");

  script_cve_id("CVE-2016-4157", "CVE-2016-4158");
  script_osvdb_id(139955, 139956);
  script_xref(name:"EDB-ID", value:"39954");

  script_name(english:"Adobe Creative Cloud Desktop < 3.7.0.272 Multiple Vulnerabilities (APSB16-21)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote
Windows host is prior to 3.7.0.272. It is, therefore, affected by
multiple vulnerabilities :

  - An untrusted search path vulnerability exists in the
    installer due to looking for specific files or libraries
    in the current working directory which may not be
    trusted or under user control. A local attacker can
    exploit this, via a specially crafted library (DLL)
    file, to inject and execute arbitrary code in the
    context of the current user. (CVE-2016-4157)

  - An unquoted search path vulnerability exists in
    AdobeUpdateService.exe that allows a local attacker to
    inject and execute arbitrary code via an executable in
    the %SYSTEMDRIVE% directory. (CVE-2016-4158)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb16-21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d20bce2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 3.7.0.272 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
highest_affected = "3.6.0.248";
fix = "3.7.0.272";

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

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
