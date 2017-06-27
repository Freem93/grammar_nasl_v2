#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73304);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2013-2871",
    "CVE-2013-2926",
    "CVE-2013-2928",
    "CVE-2013-6625",
    "CVE-2014-1289",
    "CVE-2014-1290",
    "CVE-2014-1291",
    "CVE-2014-1292",
    "CVE-2014-1293",
    "CVE-2014-1294",
    "CVE-2014-1297",
    "CVE-2014-1298",
    "CVE-2014-1299",
    "CVE-2014-1300",
    "CVE-2014-1301",
    "CVE-2014-1302",
    "CVE-2014-1303",
    "CVE-2014-1304",
    "CVE-2014-1305",
    "CVE-2014-1307",
    "CVE-2014-1308",
    "CVE-2014-1309",
    "CVE-2014-1310",
    "CVE-2014-1311",
    "CVE-2014-1312",
    "CVE-2014-1313",
    "CVE-2014-1713"
  );
  script_bugtraq_id(
    61054,
    63024,
    63028,
    63672,
    66088,
    66242,
    66243,
    66572,
    66573,
    66574,
    66575,
    66576,
    66577,
    66578,
    66579,
    66580,
    66581,
    66583,
    66584,
    66585,
    66586,
    66587
  );
  script_osvdb_id(
    95026,
    98593,
    98594,
    98595,
    99715,
    103115,
    104289,
    104290,
    104291,
    104292,
    104293,
    104294,
    104501,
    104586,
    104587,
    104600,
    105284,
    105285,
    105286,
    105287,
    105288,
    105289,
    105290,
    105291,
    105292,
    105293,
    105294,
    105295,
    105296,
    105297
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-04-01-1");

  script_name(english:"Mac OS X : Apple Safari < 6.1.3 / 7.0.3 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
a version prior to 6.1.3 or 7.0.3. It is, therefore, potentially
affected by the following vulnerabilities related to the included
WebKit components :

  - Unspecified errors exist that could allow memory
    corruption, application crashes and possibly arbitrary
    code execution. (CVE-2013-2871, CVE-2013-2926,
    CVE-2013-2928, CVE-2013-6625, CVE-2014-1289,
    CVE-2014-1290, CVE-2014-1291, CVE-2014-1292,
    CVE-2014-1293, CVE-2014-1294, CVE-2014-1298,
    CVE-2014-1299, CVE-2014-1300, CVE-2014-1301,
    CVE-2014-1302, CVE-2014-1303, CVE-2014-1304,
    CVE-2014-1305, CVE-2014-1307, CVE-2014-1308,
    CVE-2014-1309, CVE-2014-1310, CVE-2014-1311,
    CVE-2014-1312, CVE-2014-1313, CVE-2014-1713)

  - An error exists related to IPC messages and 'WebProcess'
    that could allow an attacker to read arbitrary files.
    (CVE-2014-1297)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-057/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6181");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531708/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.1.3 / 7.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.[7-9]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8 / 10.9");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if ("10.7" >< os || "10.8" >< os) fixed_version = "6.1.3";
else fixed_version = "7.0.3";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
