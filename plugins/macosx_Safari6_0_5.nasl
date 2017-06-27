#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66810);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2013-0879",
    "CVE-2013-0926",
    "CVE-2013-0991",
    "CVE-2013-0992",
    "CVE-2013-0993",
    "CVE-2013-0994",
    "CVE-2013-0995",
    "CVE-2013-0996",
    "CVE-2013-0997",
    "CVE-2013-0998",
    "CVE-2013-0999",
    "CVE-2013-1000",
    "CVE-2013-1001",
    "CVE-2013-1002",
    "CVE-2013-1003",
    "CVE-2013-1004",
    "CVE-2013-1005",
    "CVE-2013-1006",
    "CVE-2013-1007",
    "CVE-2013-1008",
    "CVE-2013-1009",
    "CVE-2013-1010",
    "CVE-2013-1011",
    "CVE-2013-1012",
    "CVE-2013-1013",
    "CVE-2013-1023"
  );
  script_bugtraq_id(
    58731,
    59326,
    59944,
    59953,
    59954,
    59955,
    59956,
    59957,
    59958,
    59959,
    59960,
    59963,
    59964,
    59965,
    59967,
    59970,
    59971,
    59972,
    59973,
    59974,
    59976,
    59977,
    60361,
    60362,
    60363,
    60364
  );
  script_osvdb_id(
    90521,
    91704,
    93470,
    93471,
    93472,
    93473,
    93474,
    93475,
    93476,
    93477,
    93478,
    93479,
    93480,
    93481,
    93482,
    93483,
    93484,
    93485,
    93486,
    93487,
    93488,
    93489,
    93915,
    93916,
    93917,
    93918
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-04-2");

  script_name(english:"Mac OS X : Apple Safari < 6.0.5 Multiple Vulnerabilities");
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
10.8 host is earlier than 6.0.5. It is, therefore, potentially
affected by several issues :

  - Multiple memory corruption vulnerabilities exist in
    WebKit that could lead to unexpected program termination
    or arbitrary code execution. (CVE-2013-0879 /
    CVE-2013-0991 / CVE-2013-0992 / CVE-2013-0993 /
    CVE-2013-0994 / CVE-2013-0995 / CVE-2013-0996 /
    CVE-2013-0997 / CVE-2013-0998 / CVE-2013-0999 /
    CVE-2013-1000 / CVE-2013-1001 / CVE-2013-1002 /
    CVE-2013-1003 / CVE-2013-1004 / CVE-2013-1005 /
    CVE-2013-1006 / CVE-2013-1007 / CVE-2013-1008 /
    CVE-2013-1009 / CVE-2013-1010 / CVE-2013-1011 /
    CVE-2013-1023)

  - A cross-site scripting issue exists in WebKit's handling
    of iframes. (CVE-2013-1012)

  - A cross-site scripting issue exists in WebKit's handling
    of copied and pasted data in HTML documents.
    (CVE-2013-0926)

  - In rewriting URLs to prevent cross-site scripting
    attacks, XSS Auditor could be abused, leading to
    malicious alteration of the behavior of a form
    submission. (CVE-2013-1013)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-107/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-108/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-109/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5785");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526807/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

fixed_version = "6.0.5";

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
