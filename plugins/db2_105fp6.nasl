#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86002);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id(
    "CVE-2015-0138",
    "CVE-2015-0197",
    "CVE-2015-0198",
    "CVE-2015-0199",
    "CVE-2015-1883",
    "CVE-2015-1922",
    "CVE-2015-1935",
    "CVE-2015-2808"
  );
  script_bugtraq_id(
    73278,
    73282,
    73283,
    73326,
    73684,
    75908,
    75911,
    75946
  );
  script_osvdb_id(
    117855,
    119390,
    119566,
    119567,
    119568,
    124500,
    124501,
    124502
  );
  script_xref(name:"IAVB", value:"2015-B-0090");

  script_name(english:"IBM DB2 10.5 < Fix Pack 6 Multiple Vulnerabilities (Bar Mitzvah)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.5 running on
the remote host is prior to Fix Pack 6. It is, therefore, affected by
the following vulnerabilities :

  - A flaw exists in the IBM Global Security Kit (GSKit)
    when handling RSA temporary keys in a non-export RSA key
    exchange ciphersuite. A man-in-the-middle attacker can
    exploit this to downgrade the session security to use
    weaker EXPORT_RSA ciphers, thus allowing the attacker to
    more easily monitor or tamper with the encrypted stream.
    (CVE-2015-0138)

  - An unspecified flaw in the General Parallel File System
    (GPFS) allows a local attacker to gain root privileges.
    (CVE-2015-0197)

  - A flaw exists in the General Parallel File System
    (GPFS), related to certain cipherList configurations,
    that allows a remote attacker, using specially crafted
    data, to bypass authentication and execute arbitrary
    programs with root privileges. (CVE-2015-0198)

  - A denial of service vulnerability exists in the General
    Parallel File System (GPFS) that allows a local attacker
    to corrupt kernel memory by sending crafted ioctl
    character device calls to the mmfslinux kernel module.
    (CVE-2015-0199)

  - An information disclosure vulnerability exists in the
    automated maintenance feature. An attacker with elevated
    privileges can exploit this issue by manipulating a
    stored procedure, resulting in the disclosure of
    arbitrary files owned by the DB2 fenced ID on UNIX/Linux
    or the administrator on Windows. (CVE-2015-1883)

  - A flaw exists in the Data Movement feature when handling
    specially crafted queries. An authenticated, remote
    attacker can exploit this to delete database rows from a
    table without having the appropriate privileges.
    (CVE-2015-1922)

  - An unspecified flaw exists when handling SQL statements
    with LUW Scaler functions. An authenticated, remote
    attacker can exploit this to run arbitrary code, under
    the privileges of the DB2 instance owner, or to cause a
    denial of service. (CVE-2015-1935)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - An information disclosure vulnerability exists due to
    improper block cipher padding by TLSv1 when using Cipher
    Block Chaining (CBC) mode. A remote attacker, via an
    'Oracle Padding' side channel attack, can exploit this
    vulnerability to gain access to sensitive information.
    Note that this is a variation of the POODLE attack.
    (NO CVE)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21633303#6");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT06351");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT06353");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT07109");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT07554");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT07635");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT08075");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT08113");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT08526");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT08537");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT08656");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/12/08/poodleagain.html");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.5 Fix Pack 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

app_name = "DB2";

level = get_kb_item_or_exit(app_name + "/" + port + "/Level");
if (level !~ "^10\.5\.")  audit(AUDIT_NOT_LISTEN, app_name + " 10.5.x", port);

platform = get_kb_item_or_exit(app_name+"/"+port+"/Platform");
platform_name = get_kb_item(app_name+"/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

report = "";

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '10.5.600.232';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
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
  fixed_level = '10.5.0.6';
  if (level =~ "^10\.5\.0\.([0-5]|3a)$")
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

if (report)
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, level);
