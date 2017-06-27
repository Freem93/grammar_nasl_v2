#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56959);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2011-2445",
    "CVE-2011-2450",
    "CVE-2011-2451",
    "CVE-2011-2452",
    "CVE-2011-2453",
    "CVE-2011-2454",
    "CVE-2011-2455",
    "CVE-2011-2456",
    "CVE-2011-2457",
    "CVE-2011-2458",
    "CVE-2011-2459",
    "CVE-2011-2460"
  );
  script_bugtraq_id(
    50618,
    50619,
    50620,
    50621,
    50622,
    50623,
    50624,
    50625,
    50626,
    50627,
    50628,
    50629
  );
  script_osvdb_id(
    77018,
    77019,
    77020,
    77021,
    77022,
    77023,
    77024,
    77025,
    77026,
    77027,
    77028,
    77029
  );

  script_name(english:"Adobe AIR <= 3.0 Multiple Vulnerabilities (APSB11-28)");
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
"According to its version, the instance of Adobe AIR installed on the
remote Windows host is 3.0 or earlier and is reportedly affected by 
several critical vulnerabilities :

  - Several unspecified memory corruption errors
    exist that could lead to code execution.
    (CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2453, CVE-2011-2454, CVE-2011-2455,
    CVE-2011-2459, CVE-2011-2460)

  - An unspecified heap corruption error exists that could
    lead to code execution. (CVE-2011-2450)

  - An unspecified buffer overflow error exists that could
    lead to code execution. (CVE-2011-2456)

  - An unspecified stack overflow error exists that could
    lead to code execution. (CVE-2011-2457)

  - An unspecified error related to Internet Explorer can
    allow cross-domain policy violations. (CVE-2011-2458)

By tricking a user on the affected system into opening a specially
crafted document with Flash content, an attacker could leverage these
vulnerabilities to execute arbitrary code remotely on the system
subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.1 (3.1.0.4880) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

fix = '3.1.0.4880';
fix_ui = '3.1';

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The Adobe AIR "+version_report+" install on the host is not affected.");
