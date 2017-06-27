#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47038);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2009-1726",
    "CVE-2010-0544",
    "CVE-2010-1119",
    "CVE-2010-1387",
    "CVE-2010-1390",
    "CVE-2010-1392",
    "CVE-2010-1393",
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
    "CVE-2010-1408",
    "CVE-2010-1409",
    "CVE-2010-1410",
    "CVE-2010-1411",
    "CVE-2010-1412",
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
    "CVE-2010-1763",
    "CVE-2010-1769",
    "CVE-2010-1770",
    "CVE-2010-1771",
    "CVE-2010-1774"
  );
  script_bugtraq_id(40657, 40663, 40697, 40710, 41053, 41054, 41125);
  script_osvdb_id(
    56845,
    61792,
    63471,
    65296,
    65300,
    65302,
    65303,
    65305,
    65306,
    65307,
    65308,
    65309,
    65310,
    65312,
    65313,
    65314,
    65316,
    65317,
    65318,
    65319,
    65321,
    65322,
    65326,
    65328,
    65329,
    65330,
    65332,
    65333,
    65334,
    65335,
    65336,
    65337,
    65338,
    65340,
    65341,
    65342,
    65655,
    65656,
    65657
  );

  script_name(english:"Apple iTunes < 9.2 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
9.2. It is, therefore, affected by multiple vulnerabilities :

  - A heap-based buffer overflow vulnerability exists in the
    handling of images with an embedded ColorSync profile.
    By using a specially crafted image, a remote attacker
    can exploit this to cause a denial of service or execute
    arbitrary code. (CVE-2009-1726)

  - Multiple integer overflow vulnerabilities exist in
    ImageIO's handling of TIFF files. By using a specially
    crafted TIFF file, a remote attacker can exploit these
    to cause a denial of service or execute arbitrary code.
    (CVE-2010-1411)

  - The WebKit component contains multiple vulnerabilities
    that can be exploited, including the execution of
    arbitrary code.
    (CVE-2010-0544, CVE-2010-1119, CVE-2010-1387,
    CVE-2010-1390, CVE-2010-1392, CVE-2010-1393,
    CVE-2010-1395, CVE-2010-1396, CVE-2010-1397,
    CVE-2010-1398, CVE-2010-1399, CVE-2010-1400,
    CVE-2010-1401, CVE-2010-1402, CVE-2010-1403,
    CVE-2010-1404, CVE-2010-1405, CVE-2010-1408,
    CVE-2010-1409, CVE-2010-1410, CVE-2010-1412,
    CVE-2010-1414, CVE-2010-1415, CVE-2010-1416,
    CVE-2010-1417, CVE-2010-1418, CVE-2010-1419,
    CVE-2010-1421, CVE-2010-1422, CVE-2010-1749,
    CVE-2010-1758, CVE-2010-1759, CVE-2010-1761,
    CVE-2010-1763, CVE-2010-1769, CVE-2010-1770,
    CVE-2010-1771, CVE-2010-1774)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4220");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Jun/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type != 'Windows') audit(AUDIT_OS_NOT, "Windows");

fixed_version = "9.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
