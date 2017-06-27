#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73968);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id(
    "CVE-2013-0408",
    "CVE-2013-3829",
    "CVE-2013-4002",
    "CVE-2013-4041",
    "CVE-2013-5372",
    "CVE-2013-5375",
    "CVE-2013-5456",
    "CVE-2013-5457",
    "CVE-2013-5458",
    "CVE-2013-5772",
    "CVE-2013-5774",
    "CVE-2013-5776",
    "CVE-2013-5778",
    "CVE-2013-5780",
    "CVE-2013-5782",
    "CVE-2013-5783",
    "CVE-2013-5784",
    "CVE-2013-5787",
    "CVE-2013-5788",
    "CVE-2013-5789",
    "CVE-2013-5790",
    "CVE-2013-5797",
    "CVE-2013-5800",
    "CVE-2013-5801",
    "CVE-2013-5802",
    "CVE-2013-5803",
    "CVE-2013-5804",
    "CVE-2013-5805",
    "CVE-2013-5806",
    "CVE-2013-5809",
    "CVE-2013-5812",
    "CVE-2013-5814",
    "CVE-2013-5817",
    "CVE-2013-5818",
    "CVE-2013-5819",
    "CVE-2013-5820",
    "CVE-2013-5823",
    "CVE-2013-5824",
    "CVE-2013-5825",
    "CVE-2013-5829",
    "CVE-2013-5830",
    "CVE-2013-5831",
    "CVE-2013-5832",
    "CVE-2013-5838",
    "CVE-2013-5840",
    "CVE-2013-5842",
    "CVE-2013-5843",
    "CVE-2013-5848",
    "CVE-2013-5849",
    "CVE-2013-5850",
    "CVE-2013-5851",
    "CVE-2013-5878",
    "CVE-2013-5884",
    "CVE-2013-5887",
    "CVE-2013-5888",
    "CVE-2013-5889",
    "CVE-2013-5893",
    "CVE-2013-5896",
    "CVE-2013-5898",
    "CVE-2013-5899",
    "CVE-2013-5902",
    "CVE-2013-5904",
    "CVE-2013-5907",
    "CVE-2013-5910",
    "CVE-2014-0368",
    "CVE-2014-0373",
    "CVE-2014-0375",
    "CVE-2014-0376",
    "CVE-2014-0387",
    "CVE-2014-0403",
    "CVE-2014-0410",
    "CVE-2014-0411",
    "CVE-2014-0415",
    "CVE-2014-0416",
    "CVE-2014-0417",
    "CVE-2014-0418",
    "CVE-2014-0422",
    "CVE-2014-0423",
    "CVE-2014-0424",
    "CVE-2014-0428",
    "CVE-2014-0892"
  );
  script_bugtraq_id(
    59204,
    61310,
    63082,
    63089,
    63095,
    63098,
    63101,
    63102,
    63103,
    63106,
    63110,
    63111,
    63112,
    63115,
    63118,
    63120,
    63121,
    63122,
    63124,
    63126,
    63128,
    63129,
    63131,
    63133,
    63134,
    63135,
    63137,
    63139,
    63141,
    63142,
    63143,
    63145,
    63146,
    63147,
    63148,
    63149,
    63150,
    63151,
    63152,
    63153,
    63154,
    63155,
    63156,
    63157,
    63158,
    63224,
    63618,
    63619,
    63620,
    63621,
    63622,
    64863,
    64875,
    64882,
    64890,
    64894,
    64899,
    64907,
    64912,
    64914,
    64915,
    64916,
    64917,
    64918,
    64919,
    64920,
    64921,
    64922,
    64923,
    64924,
    64925,
    64926,
    64927,
    64928,
    64930,
    64931,
    64932,
    64933,
    64935,
    64937,
    67014
  );
  script_osvdb_id(
    92450,
    95418,
    98524,
    98525,
    98526,
    98527,
    98528,
    98529,
    98530,
    98531,
    98532,
    98533,
    98534,
    98535,
    98536,
    98537,
    98538,
    98544,
    98546,
    98547,
    98548,
    98549,
    98550,
    98551,
    98552,
    98553,
    98554,
    98555,
    98556,
    98557,
    98558,
    98559,
    98560,
    98561,
    98562,
    98563,
    98564,
    98565,
    98566,
    98567,
    98568,
    98569,
    98571,
    98572,
    98573,
    98716,
    99529,
    99530,
    99531,
    99532,
    99533,
    101993,
    101995,
    101996,
    101997,
    102000,
    102001,
    102002,
    102003,
    102004,
    102005,
    102006,
    102007,
    102008,
    102011,
    102012,
    102013,
    102014,
    102015,
    102016,
    102017,
    102018,
    102019,
    102020,
    102021,
    102023,
    102024,
    102025,
    102027,
    102028,
    106116
  );
  script_xref(name:"CERT", value:"350089");

  script_name(english:"IBM Domino 9.x < 9.0.1 Fix Pack 1 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks version of IBM Domino");

  script_set_attribute(attribute:"synopsis", value:"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM Domino (formerly IBM Lotus Domino)
on the remote host is 9.x prior to 9.0.1 Fix Pack 1 (FP1). It is,
therefore, affected by the following vulnerabilities :

  - A stack overflow issue exists due to the insecure
    '-z execstack' flag being used during compilation, which
    could aid remote attackers in executing arbitrary code.
    Note that this issue only affects installs on 32-bit
    hosts running Linux. (CVE-2014-0892)

  - Note that the fixes in the Oracle Java CPUs for
    October 2013 and January 2014 are included in the fixed
    IBM Java release, which is included in the fixed IBM
    Domino release. (CVE-2013-0408, CVE-2013-3829,
    CVE-2013-4002, CVE-2013-4041, CVE-2013-5372,
    CVE-2013-5375, CVE-2013-5456, CVE-2013-5457,
    CVE-2013-5458, CVE-2013-5772, CVE-2013-5774,
    CVE-2013-5776, CVE-2013-5778, CVE-2013-5780,
    CVE-2013-5782, CVE-2013-5783, CVE-2013-5784,
    CVE-2013-5787, CVE-2013-5788, CVE-2013-5789,
    CVE-2013-5790, CVE-2013-5797, CVE-2013-5800,
    CVE-2013-5801, CVE-2013-5802, CVE-2013-5803,
    CVE-2013-5804, CVE-2013-5805, CVE-2013-5806,
    CVE-2013-5809, CVE-2013-5812, CVE-2013-5814,
    CVE-2013-5817, CVE-2013-5818, CVE-2013-5819,
    CVE-2013-5820, CVE-2013-5823, CVE-2013-5824,
    CVE-2013-5825, CVE-2013-5829, CVE-2013-5830,
    CVE-2013-5831, CVE-2013-5832, CVE-2013-5838,
    CVE-2013-5840, CVE-2013-5842, CVE-2013-5843,
    CVE-2013-5848, CVE-2013-5849, CVE-2013-5850,
    CVE-2013-5851, CVE-2013-5878, CVE-2013-5884,
    CVE-2013-5887, CVE-2013-5888, CVE-2013-5889,
    CVE-2013-5893, CVE-2013-5896, CVE-2013-5898,
    CVE-2013-5899, CVE-2013-5902, CVE-2013-5904,
    CVE-2013-5907, CVE-2013-5910, CVE-2014-0368,
    CVE-2014-0373, CVE-2014-0375, CVE-2014-0376,
    CVE-2014-0387, CVE-2014-0403, CVE-2014-0410,
    CVE-2014-0411, CVE-2014-0415, CVE-2014-0416,
    CVE-2014-0417, CVE-2014-0418, CVE-2014-0422,
    CVE-2014-0423, CVE-2014-0424, CVE-2014-0428,
    CVE-2014-0892)");

  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21670264");
  # 9.0.1 Fix Pack 1 release notes
  # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/ef748be11ac2e99285257ca8006fc091?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77cf0990");
  # PSIRT blog post
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/bm_security_bulletin_ibm_notes_domino_fixes_for_multiple_vulnerabilities_cve_2014_0892_and_oracle_java_critical_patch_updates_for_oct_2013_jan_2014?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd46d60e");

  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Domino 9.0.1 FP 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check the version of Domino installed.
app_name = "IBM Domino";
ver = get_kb_item_or_exit("Domino/Version");
port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;
version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;
hotfix = NULL;

# Ensure sufficient granularity.
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# Only check for 9.0.x
if (ver =~ "^9\.0($|[^0-9])")
{
  fix = "9.0.1 FP1";
  fix_ver = "9.0.1";
  fix_pack = 1;
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

# Breakdown the version into components.
version = eregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?$");
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Use 0 if no FP number. Version number itself was
# checked for in the granularity check.
if (!version[2]) version[2] = 0;
else version[2] = int(version[2]);

# Compare current to fix and report as needed.
if (
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) < 1 &&
  version[2] < fix_pack
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
