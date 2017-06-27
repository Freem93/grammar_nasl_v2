#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84505);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/26 19:18:37 $");

  script_cve_id(
    "CVE-2015-3661",
    "CVE-2015-3662",
    "CVE-2015-3663",
    "CVE-2015-3664",
    "CVE-2015-3665",
    "CVE-2015-3666",
    "CVE-2015-3667",
    "CVE-2015-3668",
    "CVE-2015-3669"
  );
  script_osvdb_id(
    123953,
    123954,
    123955,
    123956,
    123957,
    123959,
    123965,
    123966,
    123967
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-06-30-5");

  script_name(english:"Apple QuickTime < 7.7.7 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the version of QuickTime on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple QuickTime installed on the remote Windows host is
prior to 7.7.7. It is, therefore, affected by multiple
vulnerabilities :

  - An arbitrary code execution vulnerability exists due to
    improper validation of user-supplied input. An attacker
    can exploit this, with specially crafted image data in
    an SGI file, to execute arbitrary code. (CVE-2015-3661)

  - An arbitrary code execution vulnerability exists due to
    an out-of-bounds write flaw caused by improper
    validation of user-supplied input. An attacker can
    exploit this, with specially crafted image data in
    a GIF file, to execute arbitrary code. (CVE-2015-3662)

  - An arbitrary code execution vulnerability exists due to
    an out-of-bounds write flaw caused by improper
    validation of user-supplied input. An attacker can
    exploit this, with a specially crafted image descriptor
    in a GIF file, to execute arbitrary code.
    (CVE-2015-3663)

  - An overflow condition exists due to improper validation
    of user-supplied input when handling 'alis' atoms. An
    attacker can exploit this, with a specially crafted
    file, to cause a stack-based buffer overflow, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2015-3664)

  - A user-after-free error exists when handling object
    properties in movie files. An attacker can exploit this,
    with a specially crafted movie file, to dereference
    already freed memory, potentially resulting in the
    execution of arbitrary code. (CVE-2015-3665)

  - A memory corruption flaw exists due to improper
    validation of user-supplied input when handling the
    'code' atom within the 'minf' (Media Information) atom.
    An attacker can exploit this, with a specially crafted
    file, to corrupt memory, potentially resulting in the
    execution of arbitrary code. (CVE-2015-3666)

  - A user-after-free error exists in the 
    QuickTimeMPEG4!0x147f0() function when handling 'stbl'
    atoms. An attacker can exploit this, with a specially
    crafted .MOV file, to dereference already freed memory,
    potentially resulting in the execution of arbitrary
    code. (CVE-2015-3667)

  - A memory corruption flaw exists due to improper
    validation of user-supplied input when handling movie
    files. An attacker can exploit this, with a specially
    crafted file, to corrupt memory, potentially resulting
    in the execution of arbitrary code. (CVE-2015-3668)

  - An overflow condition exists due to improper validation
    of user-supplied input. An attacker can exploit this,
    with a specially crafted SGI file, to cause a heap-based
    buffer overflow, potentially resulting in the execution
    of arbitrary code. (CVE-2015-3669)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204947");
  # http://lists.apple.com/archives/security-announce/2015/Jun/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0bd6aea");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple QuickTime 7.7.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/QuickTime/";

version = get_kb_item_or_exit(kb_base+"Version");
path = get_kb_item_or_exit(kb_base+"Path");

version_ui = get_kb_item(kb_base+"Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "7.77.80.95";
fixed_version_ui = "7.7.7 (1680.95.51)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_ui +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'QuickTime Player', version_report, path);
