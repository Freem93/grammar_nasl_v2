#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89053);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/29 19:06:02 $");

  script_cve_id(
    "CVE-2015-5041",
    "CVE-2015-7575",
    "CVE-2015-7981",
    "CVE-2015-8126",
    "CVE-2015-8472",
    "CVE-2015-8540",
    "CVE-2016-0402",
    "CVE-2016-0448",
    "CVE-2016-0466",
    "CVE-2016-0475",
    "CVE-2016-0483",
    "CVE-2016-0494"
  );
  script_bugtraq_id(
    77304,
    77568,
    78624,
    79684,
    80592,
    82451
  );
  script_osvdb_id(
    129444,
    130175,
    131598,
    132305,
    133156,
    133157,
    133158,
    133159,
    133160,
    133161,
    133686
  );

  script_name(english:"AIX Java Advisory : java_jan2016_advisory.asc (January 2016 CPU) (SLOTH)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities in the following components :

  - 2D
  - AWT
  - IBM J9 JVM
  - JAXP
  - JMX
  - Libraries
  - Networking
  - Security");
  # http://aix.software.ibm.com/aix/efixes/security/java_jan2016_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ab27ddf");
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
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52d4ddf3");
  # https://www-933.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?343fa903");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/pages/attacks/SLOTH");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/downloads/transcript-collisions.pdf");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#Java6 6.0.0.535
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.534", fixpackagever:"6.0.0.535") > 0) flag++;

#Java7 7.0.0.320
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.319", fixpackagever:"7.0.0.320") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.319", fixpackagever:"7.0.0.320") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.319", fixpackagever:"7.0.0.320") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.319", fixpackagever:"7.0.0.320") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.319", fixpackagever:"7.0.0.320") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.319", fixpackagever:"7.0.0.320") > 0) flag++;

#Java7.1 7.1.0.200
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.199", fixpackagever:"7.1.0.200") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.199", fixpackagever:"7.1.0.200") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.199", fixpackagever:"7.1.0.200") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.199", fixpackagever:"7.1.0.200") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.199", fixpackagever:"7.1.0.200") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.199", fixpackagever:"7.1.0.200") > 0) flag++;

#Java8.0 8.0.0.120
if (aix_check_package(release:"6.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.119", fixpackagever:"8.0.0.120") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.119", fixpackagever:"8.0.0.120") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.119", fixpackagever:"8.0.0.120") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.119", fixpackagever:"8.0.0.120") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.119", fixpackagever:"8.0.0.120") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.119", fixpackagever:"8.0.0.120") > 0) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Java6 / Java7 / Java8");
}
