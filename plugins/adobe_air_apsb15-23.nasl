#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86059);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2015-5567",
    "CVE-2015-5568",
    "CVE-2015-5570",
    "CVE-2015-5571",
    "CVE-2015-5572",
    "CVE-2015-5573",
    "CVE-2015-5574",
    "CVE-2015-5575",
    "CVE-2015-5576",
    "CVE-2015-5577",
    "CVE-2015-5578",
    "CVE-2015-5579",
    "CVE-2015-5580",
    "CVE-2015-5581",
    "CVE-2015-5582",
    "CVE-2015-5584",
    "CVE-2015-5587",
    "CVE-2015-5588",
    "CVE-2015-6676",
    "CVE-2015-6677",
    "CVE-2015-6678",
    "CVE-2015-6679",
    "CVE-2015-6682"
  );
  script_osvdb_id(
    127803,
    127804,
    127805,
    127806,
    127807,
    127808,
    127809,
    127810,
    127811,
    127812,
    127813,
    127814,
    127815,
    127816,
    127817,
    127818,
    127819,
    127820,
    127821,
    127822,
    127823,
    127824,
    127825
  );

  script_name(english:"Adobe AIR <= 18.0.0.199 Multiple Vulnerabilities (APSB15-23)");
  script_summary(english:"Checks the version of AIR.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Windows host is equal
or prior to version 18.0.0.199. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified stack corruption issue exists that
    allows a remote attacker to execute arbitrary code.
    (CVE-2015-5567, CVE-2015-5579)

  - A vector length corruption issue exists that allows a
    remote attacker to have an unspecified impact.
    (CVE-2015-5568)

  - A use-after-free error exists in an unspecified
    component due to improperly sanitized user-supplied
    input. A remote attacker can exploit this, via a
    specially crafted file, to deference already freed
    memory and execute arbitrary code. (CVE-2015-5570,
    CVE-2015-5574, CVE-2015-5581, CVE-2015-5584,
    CVE-2015-6682)

  - An unspecified flaw exists due to a failure to reject
    content from vulnerable JSONP callback APIs. A remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-5571)

  - An unspecified flaw exists that allows a remote attacker
    to bypass security restrictions and gain access to
    sensitive information. (CVE-2015-5572)

  - An unspecified type confusion flaw exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2015-5573)

  - A flaw exists in an unspecified component due to
    improper validation of user-supplied input when handling
    a specially crafted file. A remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2015-5575,
    CVE-2015-5577, CVE-2015-5578, CVE-2015-5580,
    CVE-2015-5582, CVE-2015-5588, CVE-2015-6677)

  - A memory leak issue exists that allows a remote
    attacker to have an unspecified impact. (CVE-2015-5576)

  - A stack buffer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-5587)

  - An unspecified overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-6676,
    CVE-2015-6678)

  - An unspecified flaw exists that allows a remote attacker
    to bypass same-origin policy restrictions and gain
    access to sensitive information. (CVE-2015-6679)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-23.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 19.0.0.190 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

cutoff_version = '18.0.0.199';
fix = '19.0.0.190';
fix_ui = '19.0';

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
