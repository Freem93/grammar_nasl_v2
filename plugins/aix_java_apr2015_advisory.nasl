#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory javajsse_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(83135);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/29 19:06:02 $");

  script_cve_id("CVE-2015-0138", "CVE-2015-2808");
  script_bugtraq_id(73326, 73684);
  script_osvdb_id(117855, 119390);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"AIX Java Advisory : Multiple Vulnerabilities (Bar Mitzvah)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple TLS security downgrades.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote host is affected by
multiple vulnerabilities :

  - A man-in-the-middle information disclosure vulnerability
    exists due to a TLS security downgrade flaw. A
    man-in-the-middle attacker may be able to downgrade the
    SSL/TLS connection to use EXPORT_RSA cipher suites which
    can be factored in a short amount of time, allowing the
    attacker to intercept and decrypt the traffic.
    (CVE-2015-0138)

  - A flaw exists in the RC4 algorithm implementation due to
    improper combination of state data with key data during
    the initialization phase. A man-in-the-middle attacker
    can exploit this to conduct plaintext-recovery attacks.
    (CVE-2015-2808)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/javajsse_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/rc4_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/30");

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

#Java5 5.0.0.591
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.590", fixpackagever:"5.0.0.591") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.590", fixpackagever:"5.0.0.591") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.590", fixpackagever:"5.0.0.591") > 0) flag++;

#Java6 6.0.0.471
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.470", fixpackagever:"6.0.0.471") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.470", fixpackagever:"6.0.0.471") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.470", fixpackagever:"6.0.0.471") > 0) flag++;

#Java7 7.0.0.196
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.195", fixpackagever:"7.0.0.196") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.195", fixpackagever:"7.0.0.196") > 0) flag++;

#Java7.1 7.1.0.76
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.75", fixpackagever:"7.1.0.76") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.75", fixpackagever:"7.1.0.76") > 0) flag++;

# 64bit
#Java5 5.0.0.591
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.590", fixpackagever:"5.0.0.591") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.590", fixpackagever:"5.0.0.591") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.590", fixpackagever:"5.0.0.591") > 0) flag++;

#Java6 6.0.0.471
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.470", fixpackagever:"6.0.0.471") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.470", fixpackagever:"6.0.0.471") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.470", fixpackagever:"6.0.0.471") > 0) flag++;

#Java7 7.0.0.196
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.195", fixpackagever:"7.0.0.196") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.195", fixpackagever:"7.0.0.196") > 0) flag++;

#Java7.1 7.1.0.76
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.75", fixpackagever:"7.1.0.76") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.75", fixpackagever:"7.1.0.76") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Java5 / Java6 / Java7");
}
