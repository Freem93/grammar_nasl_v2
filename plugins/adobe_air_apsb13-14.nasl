#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66444);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2013-2728",
    "CVE-2013-3324",
    "CVE-2013-3325",
    "CVE-2013-3326",
    "CVE-2013-3327",
    "CVE-2013-3328",
    "CVE-2013-3329",
    "CVE-2013-3330",
    "CVE-2013-3331",
    "CVE-2013-3332",
    "CVE-2013-3333",
    "CVE-2013-3334",
    "CVE-2013-3335"
  );
  script_bugtraq_id(
    59889,
    59890,
    59891,
    59892,
    59893,
    59894,
    59895,
    59896,
    59897,
    59898,
    59899,
    59900,
    59901
  );
  script_osvdb_id(
    93322,
    93323,
    93324,
    93325,
    93326,
    93327,
    93328,
    93329,
    93330,
    93331,
    93332,
    93333,
    93334
  );

  script_name(english:"Adobe AIR <= 3.7.0.1530 Multiple Vulnerabilities (APSB13-14)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Adobe AIR on the remote
Windows host is 3.7.0.1530 or earlier.  It is, therefore, potentially
affected by several memory corruption errors that could lead to code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.7.0.1860 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

cutoff_version = '3.7.0.1530';
fix = '3.7.0.1860';
fix_ui = '3.7';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
