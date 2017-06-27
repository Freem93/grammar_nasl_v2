#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84828);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id(
    "CVE-2014-0919",
    "CVE-2014-6209",
    "CVE-2014-6210",
    "CVE-2014-8730",
    "CVE-2014-8901",
    "CVE-2014-8910",
    "CVE-2015-0138",
    "CVE-2015-0157",
    "CVE-2015-1788",
    "CVE-2015-1883",
    "CVE-2015-1922",
    "CVE-2015-1935",
    "CVE-2015-2808"
  );
  script_bugtraq_id(
    71549,
    71729,
    71730,
    71734,
    73326,
    73684,
    74217,
    75158,
    75908,
    75911,
    75946,
    75947,
    75949
  );
  script_osvdb_id(
    115591,
    115800,
    115801,
    115935,
    117855,
    119390,
    121576,
    123172,
    124499,
    124500,
    124501,
    124502,
    124606,
    143470,
    143471,
    143501,
    143503
  );
  script_xref(name:"IAVB", value:"2015-B-0090");
  script_xref(name:"CERT", value:"243585");

  script_name(english:"IBM DB2 9.7 < Fix Pack 11 Multiple Vulnerabilities (Bar Mitzvah) (FREAK) (TLS POODLE)");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.7 running on
the remote host is prior to Fix Pack 11. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    monitoring and audit features that occurs when handling
    a specially crafted command. An authenticated, remote
    attacker can exploit this to disclose sensitive
    information. (CVE-2014-0919)

  - A flaw exists that is triggered during the handling of a
    specially crafted ALTER TABLE statement on an identity
    column. An authenticated, remote attacker can exploit
    this to cause the server to terminate, resulting in a
    denial of service condition. (CVE-2014-6209)

  - A flaw exists that is triggered during the handling of 
    multiple ALTER TABLE statements on the same column. An
    authenticated, remote attacker can exploit this to cause
    the server to terminate, resulting in a denial of
    service condition. (CVE-2014-6210)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the TLS
    server not verifying block cipher padding when using a
    cipher suite that employs a block cipher such as AES and
    DES. The lack of padding checking can allow encrypted
    TLS traffic to be decrypted. This vulnerability could
    allow for the decryption of HTTPS traffic by an
    unauthorized third party. (CVE-2014-8730)

  - A flaw exists that is triggered when handling a
    specially crafted XML query. An authenticated, remote
    attacker can exploit this to cause excessive consumption
    of CPU resources, resulting in a denial of service
    condition. (CVE-2014-8901)

  - An unspecified error exists during the handling of
    SELECT statements with XML/XSLT functions that allows a
    remote attacker to gain access to arbitrary files.
    (CVE-2014-8910)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists in the IBM
    Global Security Kit (GSKit) due to the support of weak
    EXPORT_RSA cipher suites with keys less than or equal to
    512 bits. A man-in-the-middle attacker may be able to
    downgrade the SSL/TLS connection to use EXPORT_RSA
    cipher suites which can be factored in a short amount of
    time, allowing the attacker to intercept and decrypt the
    traffic. (CVE-2015-0138)

  - A flaw exists in the LUW component when handling SQL
    statements with unspecified Scaler functions. A remote,
    authenticated attacker can exploit this to cause a
    denial of service. (CVE-2015-0157)

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - An information disclosure vulnerability exists in the
    automated maintenance feature. An attacker with elevated
    privileges, by manipulating a stored procedure, can
    exploit this issue to disclose arbitrary files owned by
    the DB2 fenced ID on UNIX/Linux or the administrator on
    Windows. (CVE-2015-1883)

  - A flaw exists in the Data Movement feature when handling
    specially crafted queries. An authenticated, remote
    attacker can exploit this to delete database rows from a
    table without having the appropriate privileges.
    (CVE-2015-1922)

  - A flaw exists when handling SQL statements having
    unspecified LUW Scaler functions. An authenticated,
    remote attacker can exploit this to run arbitrary code,
    under the privileges of the DB2 instance owner, or to
    cause a denial of service. (CVE-2015-1935)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A denial of service vulnerability exists in the query
    compiler QGM due to improper handling of duplicate reloc
    entry queries. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 143470)

  - A denial of service vulnerability exists in the
    SQLEX_FIND_GROUP() function due to improper handling of
    group name results. An authenticated, remote attacker
    can exploit this to crash the database. (VulnDB 143471)

  - A denial of service vulnerability exists in the query
    compiler QGM due to improper handling of DBCLOB column
    types. An authenticated, remote attacker can exploit
    this to crash the database. (VulnDB 143501)

  - A denial of service vulnerability exists in the
    Relational Data Services component in the
    SQLRA_GET_SECT_INFO_BY_CURSOR_NAME() function due to
    improper handling of stored procedures. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 143503");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24040935");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697987");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697988");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21698308");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21959650");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21902661");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/12/08/poodleagain.html");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.7 Fix Pack 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^9\.7\.") audit(AUDIT_NOT_LISTEN, "DB2 9.7", port);

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

report = NULL;

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.7.1100.352';
  if (ver_compare(ver:level, fix:fixed_level) < 0)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Others
else if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 ||
  platform == 30 ||
  # AIX
  platform == 20
)
{
  fixed_level = '9.7.0.11';
  if (ver_compare(ver:level, fix:fixed_level) < 0)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
else
{
  info =
    'Nessus does not support version checks against ' + report_phrase + '.\n' +
    'To help us better identify vulnerable versions, please send the platform\n' +
    'number along with details about the platform, including the operating system\n' +
    'version, CPU architecture, and DB2 version to db2-platform-info@nessus.org.\n';
  exit(1, info);
}

if (!isnull(report))
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
