#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59113);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id(
    "CVE-2011-3458",
    "CVE-2011-3459",
    "CVE-2011-3460",
    "CVE-2012-0265",
    "CVE-2012-0658",
    "CVE-2012-0659",
    "CVE-2012-0660",
    "CVE-2012-0661",
    "CVE-2012-0663",
    "CVE-2012-0664",
    "CVE-2012-0665",
    "CVE-2012-0666",
    "CVE-2012-0667",
    "CVE-2012-0668",
    "CVE-2012-0669",
    "CVE-2012-0670",
    "CVE-2012-0671"
  );
  script_bugtraq_id(
    53465,
    53467,
    53469,
    53571,
    53574,
    53576,
    53577,
    53578,
    53579,
    53580,
    53582,
    53583,
    53584
  );
  script_osvdb_id(
    78811,
    78812,
    78813,
    81929,
    81930,
    81931,
    81932,
    81933,
    81934,
    81935,
    81936,
    81937,
    81938,
    81939,
    81940,
    81941,
    81942
  );
  script_xref(name:"EDB-ID", value:"19433");

  script_name(english:"QuickTime < 7.7.2 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that may be affected
by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is
older than 7.7.2 and may be affected by the following
vulnerabilities :

  - An uninitialized memory access issue exists in the
    handling of MP4 encoded files. (CVE-2011-3458)

  - An off-by-one buffer overflow exists in the handling of
    rdrf atoms in QuickTime movie files. (CVE-2011-3459)

  - A stack-based buffer overflow exists in the QuickTime
    plugin's handling of PNG files. (CVE-2011-3460)

  - A stack-based buffer overflow exists in QuickTime's
    handling of file paths. (CVE-2012-0265)

  - A buffer overflow exists in the handling of audio sample
    tables. (CVE-2012-0658)

  - An integer overflow exists in the handling of MPEG
    files. (CVE-2012-0659)

  - An integer underflow exists in QuickTime's handling of
    audio streams in MPEG files. (CVE-2012-0660)

  - A use-after-free issue exists in the handling of
    JPEG2000 encoded movie files. (CVE-2012-0661)

  - Multiple stack overflows exist in QuickTime's handling
    of TeXML files. (CVE-2012-0663)

  - A heap overflow exists in QuickTime's handling of text
    tracks. (CVE-2012-0664)

  - A heap overflow exists in the handling of H.264 encoded
    movie files. (CVE-2012-0665)

  - A stack-based buffer overflow exists in the QuickTime
    plugin's handling of QTMovie objects. (CVE-2012-0666)

  - A signedness issue exists in the handling of QTVR movie
    files. (CVE-2012-0667)

  - A buffer overflow exists in QuickTime's handling of
    Sorenson encoded movie files. (CVE-2012-0669)

  - An integer overflow exists in QuickTime's handling of
    sean atoms. (CVE-2012-0670)

  - A memory corruption issue exists in the handling of
    .pict files. (CVE-2012-0671)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-075/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-076/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-077/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-095/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-103/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-105/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-107/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-108/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-109/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-125/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-130/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-153/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523524/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5261");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/May/msg00005.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to QuickTime 7.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime TeXML Style Element Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

kb_base = "SMB/QuickTime/";

version = get_kb_item_or_exit(kb_base+"Version");
version_ui = get_kb_item(kb_base+"Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "7.72.80.56";
fixed_version_ui = "7.7.2 (1680.56)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base+"Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : '+fixed_version_ui+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, 'QuickTime Player', version_report);
