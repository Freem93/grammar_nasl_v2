#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200911-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(42834);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-2086", "CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3109", "CVE-2008-3110", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114", "CVE-2008-3115", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5355", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107", "CVE-2009-2409", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2689", "CVE-2009-2690", "CVE-2009-2716", "CVE-2009-2718", "CVE-2009-2719", "CVE-2009-2720", "CVE-2009-2721", "CVE-2009-2722", "CVE-2009-2723", "CVE-2009-2724", "CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3886");
  script_bugtraq_id(30140, 30141, 30142, 30143, 30146, 30147, 30148, 32608, 32620, 32892, 34240, 35922, 35939, 35942, 35943, 35944, 35946, 36881);
  script_osvdb_id(46955, 46956, 46957, 46958, 46959, 46960, 46961, 46962, 46963, 46964, 46965, 46966, 46967, 50495, 50496, 50497, 50498, 50499, 50500, 50501, 50502, 50503, 50504, 50505, 50506, 50507, 50508, 50509, 50510, 50511, 50512, 50513, 50514, 50515, 50516, 50517, 53164, 53165, 53166, 53167, 53168, 53169, 53170, 53171, 53172, 53173, 53174, 53175, 53176, 53177, 53178, 56752, 56783, 56784, 56785, 56786, 56787, 56788, 56955, 56956, 56957, 56958, 56959, 56961, 56962, 56964, 56965, 56966, 56967, 56968, 57431, 59705, 59706, 59707, 59708, 59709, 59710, 59711, 59712, 59713, 59714, 59716, 59717, 59915, 59916, 59917, 59918, 59920, 59921, 59922, 59923, 59924);
  script_xref(name:"GLSA", value:"200911-02");

  script_name(english:"GLSA-200911-02 : Sun JDK/JRE: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200911-02
(Sun JDK/JRE: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in the Sun Java
    implementation. Please review the CVE identifiers referenced below and
    the associated Sun Alerts for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted JAR
    archive, applet, or Java Web Start application, possibly resulting in
    the execution of arbitrary code with the privileges of the user running
    the application. Furthermore, a remote attacker could cause a Denial of
    Service affecting multiple services via several vectors, disclose
    information and memory contents, write or execute local files, conduct
    session hijacking attacks via GIFAR files, steal cookies, bypass the
    same-origin policy, load untrusted JAR files, establish network
    connections to arbitrary hosts and posts via several vectors, modify
    the list of supported graphics configurations, bypass HMAC-based
    authentication systems, escalate privileges via several vectors and
    cause applet code to be executed with older, possibly vulnerable
    versions of the JRE.
    NOTE: Some vulnerabilities require a trusted environment, user
    interaction, a DNS Man-in-the-Middle or Cross-Site-Scripting attack.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200911-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sun JRE 1.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.5.0.22'
    All Sun JRE 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.17'
    All Sun JDK 1.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.5.0.22'
    All Sun JDK 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.17'
    All users of the precompiled 32bit Sun JRE 1.5.x should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.5.0.22'
    All users of the precompiled 32bit Sun JRE 1.6.x should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.6.0.17'
    All Sun JRE 1.4.x, Sun JDK 1.4.x, Blackdown JRE, Blackdown JDK and
    precompiled 32bit Sun JRE 1.4.x users are strongly advised to unmerge
    Java 1.4:
    # emerge --unmerge =app-emulation/emul-linux-x86-java-1.4*
    # emerge --unmerge =dev-java/sun-jre-bin-1.4*
    # emerge --unmerge =dev-java/sun-jdk-1.4*
    # emerge --unmerge dev-java/blackdown-jdk
    # emerge --unmerge dev-java/blackdown-jre
    Gentoo is ceasing support for the 1.4 generation of the Sun Java
    Platform in accordance with upstream. All 1.4 JRE and JDK versions are
    masked and will be removed shortly."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 22, 94, 119, 189, 200, 264, 287, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-java/blackdown-jre", unaffected:make_list(), vulnerable:make_list("le 1.4.2.03-r14"))) flag++;
if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable:make_list("lt 1.6.0.17"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable:make_list("lt 1.6.0.17"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable:make_list("lt 1.6.0.17"))) flag++;
if (qpkg_check(package:"dev-java/blackdown-jdk", unaffected:make_list(), vulnerable:make_list("le 1.4.2.03-r16"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sun JDK/JRE");
}
