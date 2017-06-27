#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_oct2014_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(79626);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id(
    "CVE-2014-3065",
    "CVE-2014-3566",
    "CVE-2014-4288",
    "CVE-2014-6457",
    "CVE-2014-6458",
    "CVE-2014-6466",
    "CVE-2014-6476",
    "CVE-2014-6492",
    "CVE-2014-6493",
    "CVE-2014-6502",
    "CVE-2014-6503",
    "CVE-2014-6506",
    "CVE-2014-6511",
    "CVE-2014-6512",
    "CVE-2014-6513",
    "CVE-2014-6515",
    "CVE-2014-6527",
    "CVE-2014-6531",
    "CVE-2014-6532",
    "CVE-2014-6558"
  );
  script_bugtraq_id(
    70456,
    70460,
    70468,
    70470,
    70484,
    70507,
    70518,
    70531,
    70533,
    70538,
    70544,
    70548,
    70556,
    70560,
    70565,
    70567,
    70569,
    70572,
    70574,
    71147
  );
  script_osvdb_id(
    113251,
    113315,
    113319,
    113320,
    113321,
    113322,
    113323,
    113325,
    113326,
    113327,
    113328,
    113332,
    113333,
    113334,
    113335,
    113336,
    113337,
    113338,
    113339,
    114541
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"AIX Java Advisory : java_oct2014_advisory.asc (POODLE)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote host is affected by
the following vulnerabilities :

  - A privilege escalation vulnerability in the IBM Java SDK
    allows a local attacker to inject arbitrary code into
    the shared classes cache due to a flaw in the default
    configuration for the shared classes feature. Other
    users are able to execute the injected code, which can
    allow the attacker to gain elevated privileges.
    (CVE-2014-3065)

  - Oracle Java contains the flaw related to SSLv3 CBC-mode
    ciphers known as POODLE. The vulnerability is due to the
    way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. A man-in-the-middle attacker can
    decrypt a selected byte of a cipher text in as few as
    256 tries if they are able to force a victim application
    to repeatedly send the same data over newly created SSL
    3.0 connections. (CVE-2014-3566)

  - Vulnerabilities in Oracle Java allow remote code
    execution via flaws in the Deployment subcomponent.
    (CVE-2014-4288, CVE-2014-6492, CVE-2014-6493,
    CVE-2014-6503, CVE-2014-6532)

  - A session hijacking vulnerability exists in Oracle Java
    due to a flaw related to handling of server certificate
    changes during SSL/TLS renegotiation. This allows an
    attacker to intercept communication between a client and
    server to hijack a mutually authenticated session.
    (CVE-2014-6457)

  - Privilege escalation vulnerabilities exist in Oracle
    Java within the the Deployment subcomponent.
    (CVE-2014-6458, CVE-2014-6466)

  - Data integrity vulnerabilities exist in Oracle Java
    within the the Deployment subcomponent. (CVE-2014-6476,
    CVE-2014-6515, CVE-2014-6527)

  - A privilege escalation vulnerability exists in Oracle
    Java in the resource bundle handling code of the
    'LogRecord::readObject' function within the file
    'share/classes/java/util/logging/LogRecord.java',
    which allows an attacker to bypass certain sandbox
    restrictions. (CVE-2014-6502)

  - A privilege escalation vulnerability exists in Oracle
    Java within the property processing and name handling
    code of 'share/classes/java/util/ResourceBundle.java',
    which allows an attacker to bypass certain sandbox
    restrictions. (CVE-2014-6506)

  - Oracle Java contains an unspecified vulnerability in the
    2D subcomponent. (CVE-2014-6511)

  - An information disclosure vulnerability exists in Oracle
    Java due to a flaw related to the wrapping of datagram
    sockets in the DatagramSocket implementation. This issue
    may cause packets to be read that originate from other
    sources than the connected, thus allowing a remote
    attacker to carry out IP spoofing. (CVE-2014-6512)

  - A flaw exists in the way splash images are handled by
    'windows/native/sun/awt/splashscreen/splashscreen_sys.c'
    which allows remote code execution. (CVE-2014-6513)

  - A privilege escalation vulnerability exists in Oracle
    Java in 'share/classes/java/util/logging/Logger.java'
    because it fails to check permissions in certain cases,
    allowing an attacker to bypass sandbox restrictions and
    view or edit logs. (CVE-2014-6531)

  - A flaw related to input cipher streams within the file
    'share/classes/javax/crypto/CipherInputStream.java' can
    allow a remote attacker to affect the data integrity.
    (CVE-2014-6558)");
  # http://aix.software.ibm.com/aix/efixes/security/java_oct2014_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82bbaf9e");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aacaab25");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70623e16");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d08dc51");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ca2561a");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a624fae8");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa3fc787");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e42e2673");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae6bb0ba");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/developerworks/java/jdk/aix/service.html#levels");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/28");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#Java5 5.0.0.580
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.579", fixpackagever:"5.0.0.580") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.579", fixpackagever:"5.0.0.580") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.579", fixpackagever:"5.0.0.580") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.579", fixpackagever:"5.0.0.580") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.579", fixpackagever:"5.0.0.580") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.579", fixpackagever:"5.0.0.580") > 0) flag++;

#Java6 6.0.0.460
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.459", fixpackagever:"6.0.0.460") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.459", fixpackagever:"6.0.0.460") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.459", fixpackagever:"6.0.0.460") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.459", fixpackagever:"6.0.0.460") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.459", fixpackagever:"6.0.0.460") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.459", fixpackagever:"6.0.0.460") > 0) flag++;

#Java7 7.0.0.135
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.134", fixpackagever:"7.0.0.135") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.134", fixpackagever:"7.0.0.135") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.134", fixpackagever:"7.0.0.135") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.134", fixpackagever:"7.0.0.135") > 0) flag++;

#Java7.1 7.1.0.15
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.14", fixpackagever:"7.1.0.15") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.14", fixpackagever:"7.1.0.15") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.14", fixpackagever:"7.1.0.15") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.14", fixpackagever:"7.1.0.15") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Java5 / Java6 / Java7");
}
