#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73969);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/08 17:24:33 $");

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
    "CVE-2014-0428"
  );
  script_bugtraq_id(
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
    64937
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
    102028
  );

  script_name(english:"IBM Domino 8.0.x / 8.5.x / 9.0.x with IBM Java < 1.6 SR15 FP1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the bundled Java version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Domino (formerly Lotus Domino)
8.0.x / 8.5.x / 9.0.x that is bundled with an IBM Java version prior
to 1.6 SR15 FP1. It is, therefore, affected by the vulnerabilities
mentioned in the Oracle Java Critical Patch Update advisories for
October 2013 and January 2014.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21670264");
  # 9.0.1 Fix Pack 1 release notes
  # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/ef748be11ac2e99285257ca8006fc091?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77cf0990");
  # PSIRT blog post
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/bm_security_bulletin_ibm_notes_domino_fixes_for_multiple_vulnerabilities_cve_2014_0892_and_oracle_java_critical_patch_updates_for_oct_2013_jan_2014?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd46d60e");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino 9.0.1 FP 1 or later. Alternatively, apply the
JVM patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("SMB/Domino/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "IBM Domino";
kb_base = "SMB/Domino/";

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

domino_ver = get_kb_item_or_exit(kb_base + 'Version');
java_ver   = get_kb_item_or_exit(kb_base + 'Java_Version');
path       = get_kb_item_or_exit(kb_base + 'Path');

# Fixed jvm.dll version for 1.6 SR15 FP1
java_fix   = '2.4.2.49584';
report_fix = NULL;

# Versions 8.0.x / 8.5.x / 9.0.x affected
if (domino_ver =~ "^8\.[05]($|[^0-9])")   report_fix = '1.6 SR15 FP1 ('+java_fix+')';
else if (domino_ver =~ "^9\.0($|[^0-9])") report_fix = '1.6 SR15 FP1 ('+java_fix+') included in Domino 9.0.1 FP1)';
else audit(AUDIT_INST_PATH_NOT_VULN, appname, domino_ver, path);

if (ver_compare(ver:java_ver, fix:java_fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path                     : ' + path +
      '\n  Domino installed version : ' + domino_ver +
      '\n  JVM installed version    : ' + java_ver +
      '\n  JVM fixed version        : ' + report_fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "IBM Domino's Java Virtual Machine", java_ver, path);
