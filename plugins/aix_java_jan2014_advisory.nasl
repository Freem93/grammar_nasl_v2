#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_jan2014_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(76871);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/01 17:47:58 $");

  script_cve_id(
    "CVE-2013-5878",
    "CVE-2013-5884",
    "CVE-2013-5887",
    "CVE-2013-5888",
    "CVE-2013-5889",
    "CVE-2013-5896",
    "CVE-2013-5898",
    "CVE-2013-5899",
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
    "CVE-2014-0422",
    "CVE-2014-0423",
    "CVE-2014-0424",
    "CVE-2014-0428"
  );
  script_bugtraq_id(
    64875,
    64882,
    64894,
    64899,
    64907,
    64912,
    64914,
    64915,
    64916,
    64918,
    64919,
    64920,
    64921,
    64922,
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
    101995,
    101996,
    101997,
    102001,
    102002,
    102003,
    102004,
    102005,
    102006,
    102007,
    102008,
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

  script_name(english:"AIX Java Advisory : java_jan2014_advisory.asc");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote host is potentially
affected by the following vulnerabilities :

  - Vulnerabilities in Oracle Java allow a remote attacker
    to bypass security features through flaws in XML
    document parsing. (CVE-2013-5878, CVE-2013-5910)

  - An information disclosure flaw in Oracle Java allows a
    remote attacker access to sensitive information through
    a flaw in the COBRA component. (CVE-2013-5884)

  - A vulnerability in Oracle Java allows a remote attacker
    to conduct a denial of service attack through a flaw in
    the Deployment component. (CVE-2013-5887)

  - Unspecified vulnerabilities exist in Oracle Java due
    to flaws in the Deployment component. (CVE-2013-5888,
    CVE-2013-5898, CVE-2013-5899, CVE-2014-0375,
    CVE-2014-0403, CVE-2014-0424)

  - Vulnerabilities in Oracle Java allow remote code
    execution through a flaw in the Deployment component.
    (CVE-2013-5889, CVE-2014-0387, CVE-2014-0410,
    CVE-2014-0415)

  - A vulnerability in Oracle Java allows a remote attacker
    to conduct a denial of service attack through a flaw in
    the COBRA component. (CVE-2013-5896)

  - A vulnerability in Oracle Java allows remote code
    execution through a flaw in the 2D component.
    (CVE-2013-5907)

  - An information disclosure and security bypass flaw exist
    in Oracle Java's Networking component. (CVE-2014-0368)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in the
    Serviceability component. (CVE-2014-0373)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in the JAXP
    component. (CVE-2014-0376)

  - An information disclosure flaw in Oracle Java allows a
    remote attacker access to information about encryption
    keys through a flaw in the JSSE component.
    (CVE-2014-0411)

  - A vulnerability in Oracle Java allows a remote attacker
    to bypass security features through flaws in the JAAS
    component. (CVE-2014-0416)

  - An unspecified vulnerability exists in Oracle Java due
    to flaws in the 2D component. (CVE-2014-0417)

  - A vulnerability in Oracle Java allows remote code
    execution through a flaw in the JNDI component.
    (CVE-2014-0422)

  - An information disclosure and denial of service flaw
    exist in Oracle Java's Beans component when XML data is
    read. (CVE-2014-0423)

  - A vulnerability in Oracle Java allows remote code
    execution through a flaw in the COBRA component.
    (CVE-2014-0428)");
  # http://aix.software.ibm.com/aix/efixes/security/java_jan2014_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6aa2211");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aacaab25");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70623e16");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d08dc51");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ca2561a");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a624fae8");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa3fc787");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
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

#Java5 5.0.0.560
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.559", fixpackagever:"5.0.0.560") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.559", fixpackagever:"5.0.0.560") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.559", fixpackagever:"5.0.0.560") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.559", fixpackagever:"5.0.0.560") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.559", fixpackagever:"5.0.0.560") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.559", fixpackagever:"5.0.0.560") > 0) flag++;

#Java6 6.0.0.435
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.434", fixpackagever:"6.0.0.435") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.434", fixpackagever:"6.0.0.435") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.434", fixpackagever:"6.0.0.435") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.434", fixpackagever:"6.0.0.435") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.434", fixpackagever:"6.0.0.435") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.434", fixpackagever:"6.0.0.435") > 0) flag++;

#Java7 7.0.0.110
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.109", fixpackagever:"7.0.0.110") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.109", fixpackagever:"7.0.0.110") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.109", fixpackagever:"7.0.0.110") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.109", fixpackagever:"7.0.0.110") > 0) flag++;


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
