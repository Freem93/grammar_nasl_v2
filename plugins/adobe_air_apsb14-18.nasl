#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77171);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id(
    "CVE-2014-0538",
    "CVE-2014-0540",
    "CVE-2014-0541",
    "CVE-2014-0542",
    "CVE-2014-0543",
    "CVE-2014-0544",
    "CVE-2014-0545",
    "CVE-2014-5333"
  );
  script_bugtraq_id(
    69190,
    69191,
    69192,
    69194,
    69195,
    69196,
    69197,
    69320
  );

  script_name(english:"Adobe AIR <= AIR 14.0.0.110 Multiple Vulnerabilities (APSB14-18)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR on the remote
Windows host is equal or prior to 14.0.0.110. It is, therefore,
affected by the following vulnerabilities :

  - A use-after-free error exits that allows code
    execution. (CVE-2014-0538)

  - An unspecified security bypass error exists.
    (CVE-2014-0541)

  - Multiple errors exist related to memory leaks that can
    be used to bypass memory address randomization.
    (CVE-2014-0540, CVE-2014-0542, CVE-2014-0543,
    CVE-2014-0544, CVE-2014-0545)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-18.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 14.0.0.178 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

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

cutoff_version = '14.0.0.110';
fix = '14.0.0.178';
fix_ui = '14.0';

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
