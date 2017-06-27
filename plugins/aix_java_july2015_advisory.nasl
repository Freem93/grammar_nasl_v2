#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_july2015_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(85447);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2015-1931",
    "CVE-2015-2590",
    "CVE-2015-2601",
    "CVE-2015-2613",
    "CVE-2015-2619",
    "CVE-2015-2621",
    "CVE-2015-2625",
    "CVE-2015-2632",
    "CVE-2015-2637",
    "CVE-2015-2638",
    "CVE-2015-2664",
    "CVE-2015-4000",
    "CVE-2015-4729",
    "CVE-2015-4731",
    "CVE-2015-4732",
    "CVE-2015-4733",
    "CVE-2015-4736",
    "CVE-2015-4748",
    "CVE-2015-4749",
    "CVE-2015-4760"
  );
  script_bugtraq_id(
    74733,
    75784,
    75813,
    75818,
    75823,
    75832,
    75833,
    75850,
    75854,
    75857,
    75861,
    75867,
    75871,
    75874,
    75881,
    75883,
    75890,
    75892,
    75895,
    75985
  );
  script_osvdb_id(
    122331,
    124489,
    124617,
    124619,
    124621,
    124622,
    124623,
    124624,
    124625,
    124627,
    124628,
    124629,
    124630,
    124631,
    124633,
    124634,
    124636,
    124637,
    124639,
    124946
  );

  script_name(english:"AIX Java Advisory : java_july2015_advisory.asc (Logjam)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities :

  - Java Security Components store plaintext data in memory
    dumps, which allows a local attacker to gain access to
    sensitive information. (CVE-2015-1931)

  - A flaw exists in the readSerialData() function in
    class ObjectInputStream.java when handling OIS data,
    which allows an attacker to execute arbitrary code.
    (CVE-2015-2590)

  - Multiple flaws exist in the JCE component due to
    various cryptographic operations using non-constant
    time comparisons. A remote attacker can exploit this
    to conduct timing attacks to gain access to sensitive
    information. (CVE-2015-2601)

  - A flaw exists in the ECDH_Derive() function in file
    ec.c due to missing EC parameter validation when
    performing ECDH key derivation. A remote attacker can
    exploit this to access sensitive information.
    (CVE-2015-2613)

  - An unspecified vulnerability exists in the 2D component
    that allows a remote attacker to access sensitive
    information. (CVE-2015-2619, CVE-2015-2637)

  - A flaw exists in the RMIConnectionImpl constructor
    in class RMIConnectionImpl.java due to improper
    permission checks when creating repository class
    loaders. An attacker can exploit this to bypass sandbox
    restrictions and access sensitive information.
    (CVE-2015-2621)

  - An unspecified flaw exists in the JSSE component when
    handling the SSL/TLS protocol. A remote attacker can
    exploit this to gain access to sensitive information.
    (CVE-2015-2625)

  - An integer overflow condition exists in the
    International Components for Unicode for C/C++ (ICU4C).
    An attacker, using a specially crafted font, can exploit
    this to crash an application using this library or
    access memory contents. (CVE-2015-2632)

  - A unspecified vulnerability exists in the 2D component
    that allows a remote attacker to execute arbitrary
    code. (CVE-2015-2638)

  - An unspecified flaw exists in the Deployment component
    that allows a local attacker to gain elevated
    privileges. (CVE-2015-2664)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - An unspecified vulnerability exists in the Deployment
    component that impacts confidentiality and integrity.
    (CVE-2015-4729)

  - A flaw exists in class MBeanServerInvocationHandler.java
    when handling MBean connection proxy classes. An
    attacker can exploit this to bypass sandbox restrictions
    and execute arbitrary code. (CVE-2015-4731)

  - Multiple flaws exist in classes ObjectInputStream.java
    and SerialCallbackContext.java related to insufficient
    context checking. An attacker can exploit these to
    execute arbitrary code. (CVE-2015-4732)

  - A flaw exists in the invoke() method in the class
    RemoteObjectInvocationHandler.java due to calls to the
    finalize() method being permitted. An attacker can
    exploit this to bypass sandbox protections and execute
    arbitrary code. (CVE-2015-4733)

  - An unspecified flaw exists in the Deployment component
    that allows a local attacker to execute arbitrary code.
    (CVE-2015-4736)

  - A flaw exists in the Security component when handling
    Online Certificate Status Protocol (OCSP) responses with
    no 'nextUpdate'. A remote attacker can exploit this to
    cause an application to accept a revoked X.509
    certificate. (CVE-2015-4748)

  - An flaw exists in the query() method in class
    DnsClient.java due to a failure by the JNDI component's
    exception handling to release request information. A
    remote attacker can exploit this to cause a denial of
    service. (CVE-2015-4749)

  - An integer overflow condition exists in the layout
    engine in the International Components for Unicode for
    C/C++ (ICU4C). An attacker, using a specially crafted
    font, can exploit this to crash an application using
    this library or execute arbitrary code. (CVE-2015-4760)");
  # http://aix.software.ibm.com/aix/efixes/security/java_july2015_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa618d23");
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
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

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

#Java5 5.0.0.615
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.614", fixpackagever:"5.0.0.615") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.614", fixpackagever:"5.0.0.615") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.614", fixpackagever:"5.0.0.615") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.614", fixpackagever:"5.0.0.615") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.614", fixpackagever:"5.0.0.615") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.614", fixpackagever:"5.0.0.615") > 0) flag++;

#Java6 6.0.0.495
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.494", fixpackagever:"6.0.0.495") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.494", fixpackagever:"6.0.0.495") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.494", fixpackagever:"6.0.0.495") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.494", fixpackagever:"6.0.0.495") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.494", fixpackagever:"6.0.0.495") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.494", fixpackagever:"6.0.0.495") > 0) flag++;

#Java7 7.0.0.255
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.254", fixpackagever:"7.0.0.255") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.254", fixpackagever:"7.0.0.255") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.254", fixpackagever:"7.0.0.255") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.254", fixpackagever:"7.0.0.255") > 0) flag++;

#Java7.1 7.1.0.135
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.134", fixpackagever:"7.1.0.135") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.134", fixpackagever:"7.1.0.135") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.134", fixpackagever:"7.1.0.135") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.134", fixpackagever:"7.1.0.135") > 0) flag++;

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
