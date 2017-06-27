#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46837);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2010-0544",
    "CVE-2010-1119",
    "CVE-2010-1384",
    "CVE-2010-1385",
    "CVE-2010-1388",
    "CVE-2010-1389",
    "CVE-2010-1390",
    "CVE-2010-1391",
    "CVE-2010-1392",
    "CVE-2010-1393",
    "CVE-2010-1394",
    "CVE-2010-1395",
    "CVE-2010-1396",
    "CVE-2010-1397",
    "CVE-2010-1398",
    "CVE-2010-1399",
    "CVE-2010-1400",
    "CVE-2010-1401",
    "CVE-2010-1402",
    "CVE-2010-1403",
    "CVE-2010-1404",
    "CVE-2010-1405",
    "CVE-2010-1406",
    "CVE-2010-1408",
    "CVE-2010-1409",
    "CVE-2010-1410",
    "CVE-2010-1412",
    "CVE-2010-1413",
    "CVE-2010-1414",
    "CVE-2010-1415",
    "CVE-2010-1416",
    "CVE-2010-1417",
    "CVE-2010-1418",
    "CVE-2010-1419",
    "CVE-2010-1421",
    "CVE-2010-1422",
    "CVE-2010-1749",
    "CVE-2010-1758",
    "CVE-2010-1759",
    "CVE-2010-1761",
    "CVE-2010-1762",
    "CVE-2010-1764",
    "CVE-2010-1770",
    "CVE-2010-1771",
    "CVE-2010-1774",
    "CVE-2010-2264"
  );
  script_bugtraq_id(
    40642,
    40644,
    40645,
    40646,
    40647,
    40649,
    40650,
    40652,
    40653,
    40654,
    40655,
    40656,
    40658,
    40659,
    40660,
    40661,
    40663,
    40665,
    40666,
    40667,
    40668,
    40670,
    40671,
    40672,
    40673,
    40675,
    40697,
    40698,
    40704,
    40705,
    40707,
    40710,
    40714,
    40717,
    40726,
    40727,
    40732,
    40733,
    40750,
    40752,
    40753,
    40754,
    40756
  );
  script_osvdb_id(
    61792,
    63471,
    65299,
    65300,
    65301,
    65302,
    65303,
    65304,
    65305,
    65306,
    65307,
    65308,
    65309,
    65310,
    65311,
    65312,
    65313,
    65314,
    65315,
    65316,
    65317,
    65318,
    65319,
    65320,
    65321,
    65322,
    65323,
    65325,
    65326,
    65327,
    65328,
    65329,
    65330,
    65331,
    65332,
    65333,
    65334,
    65335,
    65336,
    65337,
    65338,
    65339,
    65340,
    65341,
    65342
  );

  script_name(english:"Mac OS X : Apple Safari < 5.0 / 4.1");
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
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 5.0 / 4.1. As such, it is potentially affected by
numerous issues in the following components :

  - Safari

  - WebKit"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4196");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Jun/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.0 / 4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "4.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0 / 4.1\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
