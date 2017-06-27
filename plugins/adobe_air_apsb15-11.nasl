#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84158);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id(
    "CVE-2015-3096",
    "CVE-2015-3097",
    "CVE-2015-3098",
    "CVE-2015-3099",
    "CVE-2015-3100",
    "CVE-2015-3101",
    "CVE-2015-3102",
    "CVE-2015-3103",
    "CVE-2015-3104",
    "CVE-2015-3105",
    "CVE-2015-3106",
    "CVE-2015-3107",
    "CVE-2015-3108"
  );
  script_bugtraq_id(
    75080,
    75081,
    75084,
    75085,
    75086,
    75087,
    75088,
    75089,
    75090
  );
  script_osvdb_id(
    123020,
    123021,
    123022,
    123023,
    123024,
    123025,
    123026,
    123027,
    123028,
    123029,
    123030,
    123031,
    123032
  );

  script_name(english:"Adobe AIR <= 17.0.0.172 Multiple Vulnerabilities (APSB15-11)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a version of Adobe AIR installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Windows host is equal or prior to 17.0.0.172. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified vulnerability exists that allows an
    attacker to bypass the fix for CVE-2014-5333.
    (CVE-2015-3096)

  - An unspecified memory address randomization flaw exists
    on Windows 7 64-bit. (CVE-2015-3097)

  - Multiple unspecified flaws exist that allow a remote
    attacker to bypass the same-origin-policy, resulting in
    the disclosure of sensitive information. (CVE-2015-3098,
    CVE-2015-3099, CVE-2015-3102)

  - A remote code execution vulnerability exists due to an
    unspecified stack overflow flaw. (CVE-2015-3100)

  - A permission flaw exists in the Flash broker for IE
    that allows an attacker to perform a privilege
    escalation. (CVE-2015-3101)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-3103,
    CVE-2015-3106, CVE-2015-3107)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-3104)

  - A memory corruption flaw exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this flaw, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3105)

  - An unspecified memory leak exists that allows an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3108)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 18.0.0.144 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Drawing Fill Shader Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

cutoff_version = '17.0.0.172';
fix = '18.0.0.144';
fix_ui = '18.0';

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
