#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78440);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id(
    "CVE-2014-0558",
    "CVE-2014-0564",
    "CVE-2014-0569",
    "CVE-2014-8439"
  );
  script_bugtraq_id(70437, 70441, 70442, 71289);
  script_osvdb_id(113197, 113198, 113199, 115035);

  script_name(english:"Adobe AIR <= AIR 15.0.0.249 Multiple Vulnerabilities (APSB14-22)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Windows host is equal or prior to 15.0.0.249. It is, therefore,
affected by the following vulnerabilities :

  - Multiple memory corruption issues due to improperly
    sanitized user-supplied input allow arbitrary code
    execution. (CVE-2014-0564, CVE-2014-0558)

  - An integer overflow issue due to improperly sanitized
    user-supplied input that allows arbitrary code
    execution. (CVE-2014-0569)

  - An arbitrary code execution vulnerability due to the
    handling of a dereferenced memory pointer.
    (CVE-2014-8439)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 15.0.0.293 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player casi32 Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

cutoff_version = '15.0.0.249';
fix = '15.0.0.293';
fix_ui = '15.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')' + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
