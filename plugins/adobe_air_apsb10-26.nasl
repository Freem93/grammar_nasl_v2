#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50604);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2010-3636",
    "CVE-2010-3637",
    "CVE-2010-3639",
    "CVE-2010-3640",
    "CVE-2010-3641",
    "CVE-2010-3642",
    "CVE-2010-3643",
    "CVE-2010-3644",
    "CVE-2010-3645",
    "CVE-2010-3646",
    "CVE-2010-3647",
    "CVE-2010-3648",
    "CVE-2010-3649",
    "CVE-2010-3650",
    "CVE-2010-3652",
    "CVE-2010-3654",
    "CVE-2010-3976"
  );
  script_bugtraq_id(
    44504,
    44671,
    44675,
    44677,
    44678,
    44679,
    44680,
    44681,
    44682,
    44683,
    44684,
    44685,
    44686,
    44687,
    44690,
    44691,
    44692
  );
  script_osvdb_id(
    68736,
    68932,
    69121,
    69122,
    69123,
    69124,
    69125,
    69126,
    69127,
    69128,
    69129,
    69130,
    69131,
    69132,
    69133,
    69135,
    69146
  );
  script_xref(name:"CERT", value:"298081");
  script_xref(name:"Secunia", value:"41917");

  script_name(english:"Adobe AIR < 2.5.1 Multiple Vulnerabilities (APSB10-26)");
  script_summary(english:"Checks version of Adobe AIR");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe AIR that is
earlier than 2.5.1.  Such versions are affected by multiple
vulnerabilities:

  - An error exists in the validation of input and, with
    certain server encodings, lead to a violation of cross-
    domain policy file restrictions. (CVE-2010-3636)

  - An unspecified error exists which can lead to a denial
    of service. (CVE-2010-3639)

  - An error exists in the library loading logic and can 
    lead to arbitrary code execution. (CVE-2010-3976)

  - There exist multiple memory corruption vulnerabilities 
    which can lead to arbitrary code execution.
    (CVE-2010-3637, CVE-2010-3640, CVE-2010-3641, 
    CVE-2010-3642, CVE-2010-3643, CVE-2010-3644, 
    CVE-2010-3645, CVE-2010-3646, CVE-2010-3647, 
    CVE-2010-3648, CVE-2010-3649, CVE-2010-3650, 
    CVE-2010-3652, CVE-2010-3654)");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-26.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe AIR 2.5.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "Button" Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

fix = '2.5.1.17730';
fix_ui = '2.5.1';

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The Adobe AIR "+version_report+" install is not affected.");
