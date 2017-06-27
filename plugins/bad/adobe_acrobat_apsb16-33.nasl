#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94071);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/04 16:16:17 $");

  script_cve_id(
    "CVE-2016-1089",
    "CVE-2016-1091",
    "CVE-2016-6939",
    "CVE-2016-6940",
    "CVE-2016-6941",
    "CVE-2016-6942",
    "CVE-2016-6943",
    "CVE-2016-6944",
    "CVE-2016-6945",
    "CVE-2016-6946",
    "CVE-2016-6947",
    "CVE-2016-6948",
    "CVE-2016-6949",
    "CVE-2016-6950",
    "CVE-2016-6951",
    "CVE-2016-6952",
    "CVE-2016-6953",
    "CVE-2016-6954",
    "CVE-2016-6955",
    "CVE-2016-6956",
    "CVE-2016-6957",
    "CVE-2016-6958",
    "CVE-2016-6959",
    "CVE-2016-6960",
    "CVE-2016-6961",
    "CVE-2016-6962",
    "CVE-2016-6963",
    "CVE-2016-6964",
    "CVE-2016-6965",
    "CVE-2016-6966",
    "CVE-2016-6967",
    "CVE-2016-6968",
    "CVE-2016-6969",
    "CVE-2016-6970",
    "CVE-2016-6971",
    "CVE-2016-6972",
    "CVE-2016-6973",
    "CVE-2016-6974",
    "CVE-2016-6975",
    "CVE-2016-6976",
    "CVE-2016-6977",
    "CVE-2016-6978",
    "CVE-2016-6979",
    "CVE-2016-6988",
    "CVE-2016-6993",
    "CVE-2016-6994",
    "CVE-2016-6995",
    "CVE-2016-6996",
    "CVE-2016-6997",
    "CVE-2016-6998",
    "CVE-2016-6999",
    "CVE-2016-7000",
    "CVE-2016-7001",
    "CVE-2016-7002",
    "CVE-2016-7003",
    "CVE-2016-7004",
    "CVE-2016-7005",
    "CVE-2016-7006",
    "CVE-2016-7007",
    "CVE-2016-7008",
    "CVE-2016-7009",
    "CVE-2016-7010",
    "CVE-2016-7011",
    "CVE-2016-7012",
    "CVE-2016-7013",
    "CVE-2016-7014",
    "CVE-2016-7015",
    "CVE-2016-7016",
    "CVE-2016-7017",
    "CVE-2016-7018",
    "CVE-2016-7019",
    "CVE-2016-7852",
    "CVE-2016-7853",
    "CVE-2016-7854"
  );
  script_bugtraq_id(
    93486,
    93487,
    93491,
    93494,
    93495,
    93496
  );
  script_osvdb_id(
    145419,
    145420,
    145421,
    145422,
    145423,
    145424,
    145425,
    145426,
    145427,
    145428,
    145429,
    145430,
    145431,
    145432,
    145433,
    145434,
    145435,
    145436,
    145437,
    145438,
    145439,
    145440,
    145441,
    145442,
    145443,
    145445,
    145446,
    145447,
    145448,
    145449,
    145450,
    145451,
    145452,
    145453,
    145454,
    145455,
    145456,
    145457,
    145458,
    145459,
    145460,
    145461,
    145462,
    145463,
    145464,
    145465,
    145466,
    145467,
    145468,
    145469,
    145470,
    145471,
    145472,
    145473,
    145474,
    145475,
    145476,
    145477,
    145478,
    145479,
    145480,
    145481,
    145482,
    145483,
    145484,
    145485,
    145486,
    145487,
    145488,
    145489,
    145490,
    146151,
    146152,
    146153
  );

  script_name(english:"Adobe Acrobat < 11.0.18 / 15.006.30243 / 15.020.20039 Multiple Vulnerabilities (APSB16-33)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is
prior to 11.0.18, 15.006.30243, or 15.020.20039. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-1089, CVE-2016-1091, CVE-2016-6944,
    CVE-2016-6945, CVE-2016-6946, CVE-2016-6949,
    CVE-2016-6952, CVE-2016-6953, CVE-2016-6961,
    CVE-2016-6962, CVE-2016-6963, CVE-2016-6964,
    CVE-2016-6965, CVE-2016-6967, CVE-2016-6968,
    CVE-2016-6969, CVE-2016-6971, CVE-2016-6979,
    CVE-2016-6988, CVE-2016-6993)

  - Multiple heap buffer overflow conditions exist that
    allow an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-6939, CVE-2016-6994)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-6940, CVE-2016-6941, CVE-2016-6942,
    CVE-2016-6943, CVE-2016-6947, CVE-2016-6948,
    CVE-2016-6950, CVE-2016-6951, CVE-2016-6954,
    CVE-2016-6955, CVE-2016-6956, CVE-2016-6959,
    CVE-2016-6960, CVE-2016-6966, CVE-2016-6970,
    CVE-2016-6972, CVE-2016-6973, CVE-2016-6974,
    CVE-2016-6975, CVE-2016-6976, CVE-2016-6977,
    CVE-2016-6978, CVE-2016-6995, CVE-2016-6996,
    CVE-2016-6997, CVE-2016-6998, CVE-2016-7000,
    CVE-2016-7001, CVE-2016-7002, CVE-2016-7003,
    CVE-2016-7004, CVE-2016-7005, CVE-2016-7006,
    CVE-2016-7007, CVE-2016-7008, CVE-2016-7009,
    CVE-2016-7010, CVE-2016-7011, CVE-2016-7012,
    CVE-2016-7013, CVE-2016-7014, CVE-2016-7015,
    CVE-2016-7016, CVE-2016-7017, CVE-2016-7018,
    CVE-2016-7019, CVE-2016-7852, CVE-2016-7853,
    CVE-2016-7854)

  - A security bypass vulnerability exists that allows an
    unauthenticated, remote attacker to bypass restrictions
    on JavaScript API execution. (CVE-2016-6957)

  - An unspecified security bypass vulnerability exists that
    allows an unauthenticated, remote attacker to bypass
    security restrictions. (CVE-2016-6958)

  - An integer overflow condition exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-6999)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-33.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 11.0.18 / 15.006.30243 / 15.020.20039
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Adobe Acrobat", win_local:TRUE);

constraints = [
  { "min_version" : "11", "max_version" : "11.0.17", "fixed_version" : "11.0.18" },
  { "min_version" : "15.6", "max_version" : "15.6.30201", "fixed_version" : "15.6.30243" },
  { "min_version" : "15.7", "max_version" : "15.17.20053", "fixed_version" : "15.20.20039" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
