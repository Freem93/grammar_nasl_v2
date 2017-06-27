#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_april2015_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(84087);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2015-0138",
    "CVE-2015-0192",
    "CVE-2015-0204",
    "CVE-2015-0458",
    "CVE-2015-0459",
    "CVE-2015-0469",
    "CVE-2015-0477",
    "CVE-2015-0478",
    "CVE-2015-0480",
    "CVE-2015-0486",
    "CVE-2015-0488",
    "CVE-2015-0491",
    "CVE-2015-1914",
    "CVE-2015-1916",
    "CVE-2015-2808"
  );
  script_bugtraq_id(
    71936,
    73326,
    73684,
    74072,
    74083,
    74094,
    74104,
    74111,
    74119,
    74141,
    74145,
    74147,
    74544,
    74545,
    74645
  );
  script_osvdb_id(
    15435,
    116794,
    117855,
    119390,
    120702,
    120705,
    120708,
    120709,
    120710,
    120712,
    120713,
    120714,
    121762,
    121763,
    121764
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"AIX Java Advisory : java_april2015_advisory.asc (Bar Mitzvah) (FREAK)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities :

  - The Global Security Kit (GSKit) contains a flaw due to
    improper restrictions of TLS state transitions. A
    man-in-the-middle attacker can exploit this to downgrade
    the security of a session to use EXPORT_RSA ciphers.
    This allows the attacker to more easily break the
    encryption and monitor or tamper with the encrypted
    stream. (CVE-2015-0138)

  - An unspecified flaw exists that allows an attacker to
    execute code running under a security manager with
    elevated privileges.(CVE-2015-0192)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - Multiple unspecified vulnerabilities exist in multiple
    Java subcomponents including 2D, Beans, Deployment, JCE,
    JSSE, and tools. (CVE-2015-0458, CVE-2015-0459,
    CVE-2015-0469, CVE-2015-0477, CVE-2015-0478,
    CVE-2015-0480, CVE-2015-0486, CVE-2015-0488,
    CVE-2015-0491)

  - An unspecified flaw exists that allows a remote attacker
    to bypass permission checks and gain access to sensitive
    information. (CVE-2015-1914)

  - An unspecified flaw exists due to the Socket Extension
    Provider's handling of TLS and SSL connections. A remote
    attacker can exploit this to cause a denial of service.
    (CVE-2015-1916)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)");
  # http://aix.software.ibm.com/aix/efixes/security/java_april2015_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edaaf4e5");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=5.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1889ff01");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=5.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ba751ee");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=6.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce533d8f");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=6.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17d05c61");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4595696");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9abd5252");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ee03dc1");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f7a066c");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

#Java5 5.0.0.600
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.599", fixpackagever:"5.0.0.600") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.599", fixpackagever:"5.0.0.600") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.599", fixpackagever:"5.0.0.600") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.599", fixpackagever:"5.0.0.600") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.599", fixpackagever:"5.0.0.600") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.599", fixpackagever:"5.0.0.600") > 0) flag++;

#Java6 6.0.0.480
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.479", fixpackagever:"6.0.0.480") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.479", fixpackagever:"6.0.0.480") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.479", fixpackagever:"6.0.0.480") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.479", fixpackagever:"6.0.0.480") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.479", fixpackagever:"6.0.0.480") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.479", fixpackagever:"6.0.0.480") > 0) flag++;

#Java7 7.0.0.205
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.204", fixpackagever:"7.0.0.205") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.204", fixpackagever:"7.0.0.205") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.204", fixpackagever:"7.0.0.205") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.204", fixpackagever:"7.0.0.205") > 0) flag++;

#Java7.1 7.1.0.85
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.84", fixpackagever:"7.1.0.85") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.84", fixpackagever:"7.1.0.85") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.84", fixpackagever:"7.1.0.85") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.84", fixpackagever:"7.1.0.85") > 0) flag++;

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
