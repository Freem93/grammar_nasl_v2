#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80611);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-2445", "CVE-2011-2450", "CVE-2011-2451", "CVE-2011-2452", "CVE-2011-2453", "CVE-2011-2454", "CVE-2011-2455", "CVE-2011-2456", "CVE-2011-2457", "CVE-2011-2458", "CVE-2011-2459", "CVE-2011-2460");

  script_name(english:"Oracle Solaris Third-Party Patch Update : flash (multiple_vulnerabilities_in_adobe_flashplayer4)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2451, CVE-2011-2452, CVE-2011-2453,
    CVE-2011-2454, CVE-2011-2455, CVE-2011-2459, and
    CVE-2011-2460. (CVE-2011-2445)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (heap memory corruption)
    via unspecified vectors. (CVE-2011-2450)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2452, CVE-2011-2453,
    CVE-2011-2454, CVE-2011-2455, CVE-2011-2459, and
    CVE-2011-2460. (CVE-2011-2451)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2451, CVE-2011-2453,
    CVE-2011-2454, CVE-2011-2455, CVE-2011-2459, and
    CVE-2011-2460. (CVE-2011-2452)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2454, CVE-2011-2455, CVE-2011-2459, and
    CVE-2011-2460. (CVE-2011-2453)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2453, CVE-2011-2455, CVE-2011-2459, and
    CVE-2011-2460. (CVE-2011-2454)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2453, CVE-2011-2454, CVE-2011-2459, and
    CVE-2011-2460. (CVE-2011-2455)

  - Buffer overflow in Adobe Flash Player before 10.3.183.11
    and 11.x before 11.1.102.55 on Windows, Mac OS X, Linux,
    and Solaris and before 11.1.102.59 on Android, and Adobe
    AIR before 3.1.0.4880, allows attackers to execute
    arbitrary code via unspecified vectors. (CVE-2011-2456)

  - Stack-based buffer overflow in Adobe Flash Player before
    10.3.183.11 and 11.x before 11.1.102.55 on Windows, Mac
    OS X, Linux, and Solaris and before 11.1.102.59 on
    Android, and Adobe AIR before 3.1.0.4880, allows
    attackers to execute arbitrary code via unspecified
    vectors. (CVE-2011-2457)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, when Internet Explorer is used, allows
    remote attackers to bypass the cross-domain policy via a
    crafted web site. (CVE-2011-2458)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2453, CVE-2011-2454, CVE-2011-2455, and
    CVE-2011-2460. (CVE-2011-2459)

  - Adobe Flash Player before 10.3.183.11 and 11.x before
    11.1.102.55 on Windows, Mac OS X, Linux, and Solaris and
    before 11.1.102.59 on Android, and Adobe AIR before
    3.1.0.4880, allows attackers to execute arbitrary code
    or cause a denial of service (memory corruption) via
    unspecified vectors, a different vulnerability than
    CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2453, CVE-2011-2454, CVE-2011-2455, and
    CVE-2011-2459. (CVE-2011-2460)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_adobe_flashplayer4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e412d22"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 02.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:flash");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^flash$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.2.0.3.0", sru:"SRU 2") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : flash\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "flash");
