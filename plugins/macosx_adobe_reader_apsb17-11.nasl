#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99376);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/23 14:39:44 $");

  script_cve_id(
    "CVE-2017-3011",
    "CVE-2017-3012",
    "CVE-2017-3013",
    "CVE-2017-3014",
    "CVE-2017-3015",
    "CVE-2017-3017",
    "CVE-2017-3018",
    "CVE-2017-3019",
    "CVE-2017-3020",
    "CVE-2017-3021",
    "CVE-2017-3022",
    "CVE-2017-3023",
    "CVE-2017-3024",
    "CVE-2017-3025",
    "CVE-2017-3026",
    "CVE-2017-3027",
    "CVE-2017-3028",
    "CVE-2017-3029",
    "CVE-2017-3030",
    "CVE-2017-3031",
    "CVE-2017-3032",
    "CVE-2017-3033",
    "CVE-2017-3034",
    "CVE-2017-3035",
    "CVE-2017-3036",
    "CVE-2017-3037",
    "CVE-2017-3038",
    "CVE-2017-3039",
    "CVE-2017-3040",
    "CVE-2017-3041",
    "CVE-2017-3042",
    "CVE-2017-3043",
    "CVE-2017-3044",
    "CVE-2017-3045",
    "CVE-2017-3046",
    "CVE-2017-3047",
    "CVE-2017-3048",
    "CVE-2017-3049",
    "CVE-2017-3050",
    "CVE-2017-3051",
    "CVE-2017-3052",
    "CVE-2017-3053",
    "CVE-2017-3054",
    "CVE-2017-3055",
    "CVE-2017-3056",
    "CVE-2017-3057",
    "CVE-2017-3065"
  );
  script_bugtraq_id(
    97547,
    97548,
    97549,
    97550,
    97554,
    97556
  );
  script_osvdb_id(
    155282,
    155283,
    155284,
    155285,
    155286,
    155287,
    155288,
    155289,
    155290,
    155291,
    155292,
    155293,
    155294,
    155295,
    155296,
    155297,
    155298,
    155299,
    155300,
    155301,
    155302,
    155303,
    155304,
    155305,
    155306,
    155307,
    155308,
    155309,
    155310,
    155311,
    155312,
    155313,
    155314,
    155315,
    155316,
    155317,
    155318,
    155319,
    155320,
    155321,
    155322,
    155323,
    155324,
    155325,
    155326,
    155327,
    155328
  );
  script_xref(name:"IAVA", value:"2017-A-0092");

  script_name(english:"Adobe Reader < 11.0.20 / 2015.006.30306 / 2017.009.20044 Multiple Vulnerabilities (APSB17-11) (macOS)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS or Mac OS X
host is a version prior to 11.0.20, 2015.006.30306, 2017.009.20044. It
is, therefore, affected by multiple vulnerabilities :

  - Multiple use-after-free errors exists that allow an
    attacker to execute arbitrary code. (CVE-2017-3014,
    CVE-2017-3026, CVE-2017-3027, CVE-2017-3035,
    CVE-2017-3047, CVE-2017-3057)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2017-3042, CVE-2017-3048, CVE-2017-3049,
    CVE-2017-3055)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2017-3015,
    CVE-2017-3017, CVE-2017-3018, CVE-2017-3019,
    CVE-2017-3023, CVE-2017-3024, CVE-2017-3025,
    CVE-2017-3028, CVE-2017-3030, CVE-2017-3036,
    CVE-2017-3037, CVE-2017-3038, CVE-2017-3039,
    CVE-2017-3040, CVE-2017-3041, CVE-2017-3044,
    CVE-2017-3050, CVE-2017-3051, CVE-2017-3054,
    CVE-2017-3056, CVE-2017-3065)

  - Multiple integer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2017-3011,
    CVE-2017-3034)

  - Multiple memory corruption issues exist that allow an
    an attacker to disclose memory address information.
    (CVE-2017-3020, CVE-2017-3021, CVE-2017-3022,
    CVE-2017-3029, CVE-2017-3031, CVE-2017-3032,
    CVE-2017-3033, CVE-2017-3043, CVE-2017-3045,
    CVE-2017-3046, CVE-2017-3052, CVE-2017-3053)

  - A flaw exists due the use of an insecure directory
    search path. An attacker can potentially exploit this to
    execute arbitrary code. (CVE-2017-3012, CVE-2017-3013)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 11.0.20 / 2015.006.30306 / 2017.009.20044 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"Adobe Reader");

constraints = [
  { "min_version" : "11", "max_version" : "11.0.19", "fixed_version" : "11.0.20" },
  { "min_version" : "15.6", "max_version" : "15.6.30280", "fixed_version" : "15.6.30306" },
  { "min_version" : "15.7", "max_version" : "15.23.20070", "fixed_version" : "17.9.20044" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
