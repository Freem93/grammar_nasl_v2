#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62890);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/11/14 18:42:58 $");

  script_cve_id(
    "CVE-2011-1374",
    "CVE-2012-3751",
    "CVE-2012-3752",
    "CVE-2012-3753",
    "CVE-2012-3754",
    "CVE-2012-3755",
    "CVE-2012-3756",
    "CVE-2012-3757",
    "CVE-2012-3758"
  );
  script_bugtraq_id(
    56549, 
    56550, 
    56551, 
    56552, 
    56553, 
    56556, 
    56557,
    56563,
    56564
  );
  script_osvdb_id(
    87087,
    87088,
    87089,
    87090,
    87091,
    87092,
    87093,
    87094,
    87095
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-11-07-1");
  script_xref(name:"EDB-ID", value:"22855");

  script_name(english:"QuickTime < 7.7.3 Multiple Vulnerabilities (Windows)");
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
older than 7.7.3 and therefore is reportedly affected by the
following vulnerabilities :

  - A buffer overflow exists in the handling of REGION
    records in PICT files. (CVE-2011-1374)

  - A memory corruption issue exists in the handling of
    PICT files. (CVE-2012-3757)

  - A use-after-free issue exists in the QuickTime plugin's
    handling of '_qtactivex_' parameters within an HTML 
    object element. (CVE-2012-3751)

  - A buffer overflow exists in the handling of the 
    transform attribute in text3GTrack elements in TeXML
    files. (CVE-2012-3758)

  - Multiple buffer overflows exist in the handling of
    style elements in TeXML files. (CVE-2012-3752)

  - A buffer overflow exists in the handling of MIME types.
    (CVE-2012-3753)

  - A use-after-free issue exists in the QuickTime ActiveX
    control's handling of the 'Clear()' method. 
    (CVE-2012-3754)

  - A buffer overflow exists in the handling of Targa image
    files. (CVE-2012-3755)

  - A buffer overflow exists in the handling of 'rnet' 
    boxes in MP4 files. (CVE-2012-3756)

Successful exploitation of these issues could result in program
termination or arbitrary code execution, subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5581");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Nov/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524662/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to QuickTime 7.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.7.2 MIME Type Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

fixed_version = "7.73.80.64";
fixed_version_ui = "7.7.3 (1680.64)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : '+fixed_version_ui+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'QuickTime Player', version_report, path);
