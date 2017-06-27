#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70563);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id(
    "CVE-2013-1036",
    "CVE-2013-1037",
    "CVE-2013-1038",
    "CVE-2013-1039",
    "CVE-2013-1040",
    "CVE-2013-1041",
    "CVE-2013-1042",
    "CVE-2013-1043",
    "CVE-2013-1044",
    "CVE-2013-1045",
    "CVE-2013-1046",
    "CVE-2013-1047",
    "CVE-2013-2842",
    "CVE-2013-2848",
    "CVE-2013-5125",
    "CVE-2013-5126",
    "CVE-2013-5127",
    "CVE-2013-5128",
    "CVE-2013-5129",
    "CVE-2013-5130",
    "CVE-2013-5131",
    "CVE-2013-7127"
  );
  script_bugtraq_id(
    60067,
    60073,
#   62490, Retired
    62537,
    62539,
    62541,
    62551,
    62553,
    62554,
    62556,
    62557,
    62558,
    62559,
    62560,
    62563,
    62565,
    62567,
    62568,
    62569,
    62570,
    62571,
    63289,
    64409
  );
  script_osvdb_id(
    92818,
    93577,
    97443,
    97485,
    97486,
    97488,
    97489,
    97490,
    97491,
    97492,
    97493,
    97494,
    97495,
    97496,
    97497,
    97498,
    97499,
    97500,
    97501,
    97502,
    98879,
    101118
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-2");

  script_name(english:"Mac OS X : Apple Safari < 6.1 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Safari installed on the remote Mac OS X 10.7 or
10.8 host is earlier than 6.1. It is, therefore, potentially affected
by several issues :

  - A bounds-checking issue exists related to handling XML
    files. (CVE-2013-1036)

  - Multiple memory corruption vulnerabilities exist in
    WebKit that could lead to unexpected program termination
    or arbitrary code execution. (CVE-2013-1037,
    CVE-2013-1038, CVE-2013-1039, CVE-2013-1040,
    CVE-2013-1041, CVE-2013-1042, CVE-2013-1043,
    CVE-2013-1044, CVE-2013-1045, CVE-2013-1046,
    CVE-2013-1047, CVE-2013-2842, CVE-2013-5125,
    CVE-2013-5126, CVE-2013-5127, CVE-2013-5128)

  - An error exists related to URL handling that could lead
    to information disclosure. (CVE-2013-2848)

  - A cross-site scripting issue exists in WebKit's handling
    of URLs and drag-and-drop operations. (CVE-2013-5129,
    CVE-2013-5131)

  - Using 'Web Inspector' could negate 'Private Browsing'
    protections leading to information disclosure.
    (CVE-2013-5130)

  - An error exists related to the 'Reopen All Windows
    from Last Session' feature that could allow a local
    attacker to obtain plaintext user ID and password
    information from the 'LastSession.plist' file.
    (CVE-2013-7127)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6000");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00003.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securelist.com/en/blog/8168/Loophole_in_Safari");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "6.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
