#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_jul2014_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(77333);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/01 17:47:58 $");

  script_cve_id(
    "CVE-2014-3086",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4265",
    "CVE-2014-4266",
    "CVE-2014-4268"
  );
  script_bugtraq_id(
    68571,
    68576,
    68580,
    68583,
    68596,
    68599,
    68603,
    68615,
    68620,
    68624,
    68632,
    68636,
    68639,
    68642,
    69183
  );
  script_osvdb_id(
    109124,
    109125,
    109131,
    109132,
    109133,
    109134,
    109135,
    109136,
    109137,
    109138,
    109140,
    109141,
    109142,
    109143,
    109856
  );

  script_name(english:"AIX Java Advisory : java_jul2014_advisory.asc");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote host is affected by
the following vulnerabilities :

  - A privilege escalation vulnerability in IBM Java
    Virtual Machine allows remote attackers to execute code
    to increase access in the context of a security manager.
    (CVE-2014-3086)

  - Data integrity vulnerabilities exist in Oracle Java
    within the the Deployment subcomponent. (CVE-2014-4208,
    CVE-2014-4220, CVE-2014-4265)

  - An information disclosure vulnerability in Oracle Java's
    JMX subcomponent allows a remote attacker to view or
    edit the SubjectDelegator class. (CVE-2014-4209)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features via flaws in 'Proxy.java'
    in the Libraries subcomponent. (CVE-2014-4218)

  - A vulnerability in Oracle Java allows remote code
    execution via a flaw in the Hotspot subcomponent,
    returning incomplete objects. (CVE-2014-4219)

  - An information disclosure vulnerability in Oracle Java's
    Libraries subcomponent allows a remote attacker to view
    sensitive information. (CVE-2014-4221)

  - Vulnerabilities in Oracle Java allow remote code
    execution via flaws in the Deployment subcomponent.
    (CVE-2014-4227)

  - There are information disclosure vulnerabilities in the
    Security subcomponent of Oracle Java that can allow
    remote attackers to gain sensitive information,
    including information about used keys. (CVE-2014-4244,
    CVE-2014-4252, CVE-2014-4263)

  - A vulnerability in Oracle Java allows remote code
    execution via a memory corruption flaw in the Libraries
    subcomponent. (CVE-2014-4262)

  - A data integrity vulnerability exists in Oracle Java
    within the Serviceability subcomponent due to incorrect
    function return values. (CVE-2014-4266)

  - An information disclosure vulnerability in Oracle Java's
    Swing subcomponent allows a remote attacker to view
    restricted file contents. (CVE-2014-4268)");
  # http://aix.software.ibm.com/aix/efixes/security/java_jul2014_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cd279e0");
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
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:java");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

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

#Java5 5.0.0.579
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.578", fixpackagever:"5.0.0.579") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.578", fixpackagever:"5.0.0.579") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.578", fixpackagever:"5.0.0.579") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.578", fixpackagever:"5.0.0.579") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.578", fixpackagever:"5.0.0.579") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.578", fixpackagever:"5.0.0.579") > 0) flag++;

#Java6 6.0.0.459
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.458", fixpackagever:"6.0.0.459") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.458", fixpackagever:"6.0.0.459") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.458", fixpackagever:"6.0.0.459") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.458", fixpackagever:"6.0.0.459") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.458", fixpackagever:"6.0.0.459") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.458", fixpackagever:"6.0.0.459") > 0) flag++;

#Java7 7.0.0.134
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.133", fixpackagever:"7.0.0.134") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.133", fixpackagever:"7.0.0.134") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.133", fixpackagever:"7.0.0.134") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.133", fixpackagever:"7.0.0.134") > 0) flag++;

#Java7.1 7.1.0.14
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.13", fixpackagever:"7.1.0.14") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.13", fixpackagever:"7.1.0.14") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.13", fixpackagever:"7.1.0.14") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.13", fixpackagever:"7.1.0.14") > 0) flag++;

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
