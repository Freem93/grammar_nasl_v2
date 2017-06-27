#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72706);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/31 14:51:02 $");

  script_cve_id(
    "CVE-2013-1032",
    "CVE-2014-1243",
    "CVE-2014-1244",
    "CVE-2014-1245",
    "CVE-2014-1246",
    "CVE-2014-1247",
    "CVE-2014-1248",
    "CVE-2014-1249",
    "CVE-2014-1250",
    "CVE-2014-1251"
  );
  script_bugtraq_id(62375, 65777, 65784, 65786, 65787);
  script_osvdb_id(
    97284,
    103740,
    103741,
    103742,
    103743,
    103744,
    103745,
    103746,
    103747,
    103748
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-02-25-3");

  script_name(english:"QuickTime < 7.7.5 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that may be affected
by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickTime installed on the remote Windows host is
earlier than 7.7.5.  It is, therefore, reportedly affected by the
following vulnerabilities :

  - Out-of-bounds byte swapping issues exist in the
    handling of QuickTime image descriptions and 'ttfo'
    elements. (CVE-2013-1032, CVE-2014-1250)

  - An uninitialized pointer issue exists in the handling of
    track lists.  (CVE-2014-1243)

  - Buffer overflow vulnerabilities exist in the handling of
    H.264 encoded movie files, 'ftab' atoms, 'ldat' atoms,
    PSD images, and 'clef' atoms. (CVE-2014-1244,
    CVE-2014-1248, CVE-2014-1249, CVE-2014-1251)

  - A signedness issue exists in the handling of 'stsz'
    atoms. (CVE-2014-1245)

  - A memory corruption issue exists in the handling of
    'dref' atoms. (CVE-2014-1247)

Successful exploitation of these issues could result in program
termination or arbitrary code execution, subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-044/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-045/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-046/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-047/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-048/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-049/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6151");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2014/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531268/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to QuickTime 7.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

fixed_version = "7.75.80.95";
fixed_version_ui = "7.7.5 (1680.95.13)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : '+fixed_version_ui+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'QuickTime Player', version_report, path);
