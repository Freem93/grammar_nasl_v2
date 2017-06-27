#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94970);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/22 15:29:04 $");

  script_cve_id(
    "CVE-2016-3485",
    "CVE-2016-3511",
    "CVE-2016-3598"
  );
  script_bugtraq_id(
    91918,
    91990
  );
  script_osvdb_id(
    141826,
    141829,
    141836
  );

  script_name(english:"AIX Java Advisory : java_july2016_advisory.asc (July 2016 CPU)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities in the following subcomponents :

  - An unspecified flaw exists in the Networking
    subcomponent that allows a local attacker to impact
    integrity. (CVE-2016-3485)

  - An unspecified flaw exists in the Deployment
    subcomponent that allows a local attacker to gain
    elevated privileges. (CVE-2016-3511)

  - A flaw exists in the Libraries subcomponent in the
    share/classes/java/lang/invoke/MethodHandles.java class
    within the MethodHandles::dropArguments() function that
    allows an unauthenticated, remote attacker to impact
    confidentiality, integrity, and availability.
    (CVE-2016-3598)");
  # http://aix.software.ibm.com/aix/efixes/security/java_july2016_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46a051b3");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=6.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce533d8f");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=6.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17d05c61");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4595696");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9abd5252");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ee03dc1");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f7a066c");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52d4ddf3");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?343fa903");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

#Java6 6.0.0.585
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.584", fixpackagever:"6.0.0.585") > 0) flag++;

#Java7 7.0.0.450
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.449", fixpackagever:"7.0.0.450") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.449", fixpackagever:"7.0.0.450") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.449", fixpackagever:"7.0.0.450") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.449", fixpackagever:"7.0.0.450") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.449", fixpackagever:"7.0.0.450") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.449", fixpackagever:"7.0.0.450") > 0) flag++;

#Java7.1 7.1.0.350
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.349", fixpackagever:"7.1.0.350") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.349", fixpackagever:"7.1.0.350") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.349", fixpackagever:"7.1.0.350") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.349", fixpackagever:"7.1.0.350") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.349", fixpackagever:"7.1.0.350") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.349", fixpackagever:"7.1.0.350") > 0) flag++;

#Java8.0 8.0.0.310
if (aix_check_package(release:"6.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.309", fixpackagever:"8.0.0.310") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.309", fixpackagever:"8.0.0.310") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.309", fixpackagever:"8.0.0.310") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.309", fixpackagever:"8.0.0.310") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.309", fixpackagever:"8.0.0.310") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.309", fixpackagever:"8.0.0.310") > 0) flag++;

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
