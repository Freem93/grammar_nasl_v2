#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66636);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/03/02 00:50:39 $");

  script_cve_id(
    "CVE-2013-0986",
    "CVE-2013-0987",
    "CVE-2013-0988",
    "CVE-2013-0989",
    "CVE-2013-1015",
    "CVE-2013-1016",
    "CVE-2013-1017",
    "CVE-2013-1018",
    "CVE-2013-1019",
    "CVE-2013-1020",
    "CVE-2013-1021",
    "CVE-2013-1022"
  );
  script_bugtraq_id(
    60092,
    60097,
    60098,
    60099,
    60100,
    60101,
    60102,
    60103,
    60104,
    60108,
    60109,
    60110
  );
  script_osvdb_id(
    93614,
    93615,
    93616,
    93617,
    93618,
    93619,
    93620,
    93621,
    93622,
    93623,
    93624,
    93625
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-05-22-1");

  script_name(english:"QuickTime < 7.7.4 Multiple Vulnerabilities (Windows)");
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
"The version of QuickTime installed on the remote Windows host is older
than 7.7.4.  It is, therefore, reportedly affected by the following
vulnerabilities :

  - Buffer overflow vulnerabilities exist in the handling of
    'dref' atoms, 'enof' atoms, 'mvhd' atoms, FPX files, MP3
    files, H.263 and H.264 encoded movie files, Sorenson
    encoded movie files, and  JPEG encoded data.
    (CVE-2013-0986, CVE-2013-0988, CVE-2013-0989,
    CVE-2013-1016, CVE-2013-1017, CVE-2013-1018,
    CVE-2013-1019, CVE-2013-1021, CVE-2013-1022)

  - Memory corruption vulnerabilities exist in the handling
    of QTIF files, TeXML files, and JPEG encoded data.
    (CVE-2013-0987, CVE-2013-1015, CVE-2013-1020)

Successful exploitation of these issues could result in program
termination or arbitrary code execution, subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-110/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-111/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-112/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-113/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-114/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-115/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-116/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-117/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-118/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-119/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5770");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/May/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526669/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-080/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-110/");
  script_set_attribute(attribute:"solution", value:"Upgrade to QuickTime 7.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple Quicktime 7 Invalid Atom Length Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

fixed_version = "7.74.80.86";
fixed_version_ui = "7.7.4 (1680.86)";

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
