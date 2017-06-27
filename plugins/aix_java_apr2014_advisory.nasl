#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_apr2014_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(76870);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0429",
    "CVE-2014-0446",
    "CVE-2014-0448",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-0878",
    "CVE-2014-1876",
    "CVE-2014-2398",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2409",
    "CVE-2014-2412",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_bugtraq_id(
    63676,
    64493,
    65568,
    66856,
    66866,
    66870,
    66873,
    66879,
    66881,
    66883,
    66887,
    66891,
    66894,
    66898,
    66899,
    66902,
    66903,
    66904,
    66905,
    66907,
    66909,
    66910,
    66911,
    66914,
    66915,
    66916,
    66919,
    66920,
    67601
  );
  script_osvdb_id(
    99711,
    101309,
    102808,
    105866,
    105867,
    105869,
    105873,
    105874,
    105875,
    105876,
    105877,
    105878,
    105879,
    105880,
    105881,
    105882,
    105883,
    105884,
    105885,
    105886,
    105887,
    105889,
    105890,
    105892,
    105895,
    105897,
    105898,
    105899
  );

  script_name(english:"AIX Java Advisory : java_apr2014_advisory.asc");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote host is potentially
affected by the following vulnerabilities :

  - There is an information disclosure flaw in libjpeg and
    libjpeg-turbo allowing remote attackers access to
    uninitialized memory via crafted JPEG images.
    (CVE-2013-6629)

  - A vulnerability in libpng allows denial of service
    attacks via a flaw in pngtran.c pngset.c.
    (CVE-2013-6954)

  - Vulnerabilities in Oracle Java allow remote code
    execution via flaws in 2D image handling.
    (CVE-2014-0429, CVE-2014-2401, CVE-2014-2421)

  - A vulnerability in Oracle Java allows remote code
    execution via a flaw in logger handling.
    (CVE-2014-0446)

  - Vulnerabilities in Oracle Java allow remote code
    execution via flaws in the Deployment subcomponent.
    (CVE-2014-0448, CVE-2014-0449, CVE-2014-2409,
    CVE-2014-2420, CVE-2014-2428)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in AWT.
    (CVE-2014-0451, CVE-2014-2412)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in
    W3CEndpointReference.java. (CVE-2014-0452)

  - An information disclosure vulnerability in Oracle Java
    RSAPadding allows a remote attacker to view timing
    information protected by encryption. (CVE-2014-0452)

  - A vulnerability in Oracle Java allows a remote attacker
    to modify the SIGNATURE_PRIMITIVE_SET through flaws in
    SignatureAndHalshAlgorithm and AlgorithmChecker.
    (CVE-2014-0454)

  - A vulnerability in Oracle Java allows remote code
    execution via a flaw in MethodHandles.java.
    (CVE-2014-0455)

  - A vulnerability in Oracle Java allows remote code
    execution via a flaw in exception handling.
    (CVE-2014-0457)

  - Vulnerabilities in Oracle Java allow a remote attacker
    to bypass security features through flaws in JAX-WS.
    (CVE-2014-0458, CVE-2014-2423)

  - An unspecified vulnerability exists in Oracle Java
    via sandboxed applications.
    (CVE-2014-0459)

  - A vulnerability in Oracle Java allows remote attackers
    to conduct spoofing attacks via a flaw in the DnsClient
    component. (CVE-2014-0460)

  - A vulnerability in Oracle Java allows remote code
    execution via a flaw in ScriptEngineManager.java.
    (CVE-2014-0461)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in the random
    number generation of cryptographic protection.
    (CVE-2014-0878)

  - A privilege escalation vulnerability in Oracle Java
    allows remote attacks to overwrite arbitrary files
    via a flaw in unpack200. (CVE-2014-1876)

  - A vulnerability in Oracle Java allows remote code
    execution via a flaw in Javadoc. (CVE-2014-2398)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in
    asynchronous channel handling across threads.
    (CVE-2014-2402)

  - Vulnerabilities in Oracle Java allow a remote attacker
    to bypass security features through flaws in JAXB.
    (CVE-2014-2414)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in Java sound
    libraries. (CVE-2014-2427)");
  # http://aix.software.ibm.com/aix/efixes/security/java_apr2014_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63277512");
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
"Fixes are available by version and can be downloaded from the AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:java");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/28");

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

#Java5 5.0.0.575
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.574", fixpackagever:"5.0.0.575") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.574", fixpackagever:"5.0.0.575") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.574", fixpackagever:"5.0.0.575") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.574", fixpackagever:"5.0.0.575") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.574", fixpackagever:"5.0.0.575") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.574", fixpackagever:"5.0.0.575") > 0) flag++;

#Java6 6.0.0.455
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.454", fixpackagever:"6.0.0.455") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.454", fixpackagever:"6.0.0.455") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.454", fixpackagever:"6.0.0.455") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.454", fixpackagever:"6.0.0.455") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.454", fixpackagever:"6.0.0.455") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.454", fixpackagever:"6.0.0.455") > 0) flag++;

#Java7 7.0.0.130
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.129", fixpackagever:"7.0.0.130") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.129", fixpackagever:"7.0.0.130") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.129", fixpackagever:"7.0.0.130") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.129", fixpackagever:"7.0.0.130") > 0) flag++;

#Java7.1 7.1.0.10
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.9", fixpackagever:"7.1.0.10") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.9", fixpackagever:"7.1.0.10") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.9", fixpackagever:"7.1.0.10") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.9", fixpackagever:"7.1.0.10") > 0) flag++;

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
