#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32013);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-5232", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689", "CVE-2008-0628", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_osvdb_id(35483, 36199, 36200, 37756, 37759, 37760, 37761, 37762, 37763, 37765, 40834, 40931, 41146, 41147, 42589, 42590, 42591, 42592, 42593, 42594, 42595, 42596, 42597, 42598, 42599, 42600, 42601, 42602, 45527);
  script_xref(name:"GLSA", value:"200804-20");

  script_name(english:"GLSA-200804-20 : Sun JDK/JRE: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200804-20
(Sun JDK/JRE: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Sun Java:
    Daniel Soeder discovered that a long codebase attribute string in a
    JNLP file will overflow a stack variable when launched by Java WebStart
    (CVE-2007-3655).
    Multiple vulnerabilities (CVE-2007-2435, CVE-2007-2788,
    CVE-2007-2789) that were previously reported as GLSA 200705-23 and GLSA
    200706-08 also affect 1.4 and 1.6 SLOTs, which was not mentioned in the
    initial revision of said GLSAs.
    The Zero Day Initiative, TippingPoint and John Heasman reported
    multiple buffer overflows and unspecified vulnerabilities in Java Web
    Start (CVE-2008-1188, CVE-2008-1189, CVE-2008-1190,
    CVE-2008-1191).
    Hisashi Kojima of Fujitsu and JPCERT/CC reported a security issue
    when performing XSLT transformations (CVE-2008-1187).
    CERT/CC reported a Stack-based buffer overflow in Java Web Start
    when using JNLP files (CVE-2008-1196).
    Azul Systems reported an unspecified vulnerability that allows
    applets to escalate their privileges (CVE-2007-5689).
    Billy Rios, Dan Boneh, Collin Jackson, Adam Barth, Andrew Bortz,
    Weidong Shao, and David Byrne discovered multiple instances where Java
    applets or JavaScript programs run within browsers do not pin DNS
    hostnames to a single IP address, allowing for DNS rebinding attacks
    (CVE-2007-5232, CVE-2007-5273, CVE-2007-5274).
    Peter Csepely reported that Java Web Start does not properly
    enforce access restrictions for untrusted applications (CVE-2007-5237,
    CVE-2007-5238).
    Java Web Start does not properly enforce access restrictions for
    untrusted Java applications and applets, when handling drag-and-drop
    operations (CVE-2007-5239).
    Giorgio Maone discovered that warnings for untrusted code can be
    hidden under applications' windows (CVE-2007-5240).
    Fujitsu reported two security issues where security restrictions of
    web applets and applications were not properly enforced (CVE-2008-1185,
    CVE-2008-1186).
    John Heasman of NGSSoftware discovered that the Java Plug-in does
    not properly enforce the same origin policy (CVE-2008-1192).
    Chris Evans of the Google Security Team discovered multiple
    unspecified vulnerabilities within the Java Runtime Environment Image
    Parsing Library (CVE-2008-1193, CVE-2008-1194).
    Gregory Fleischer reported that web content fetched via the 'jar:'
    protocol was not subject to network access restrictions
    (CVE-2008-1195).
    Chris Evans and Johannes Henkel of the Google Security Team
    reported that the XML parsing code retrieves external entities even
    when that feature is disabled (CVE-2008-0628).
    Multiple unspecified vulnerabilities might allow for escalation of
    privileges (CVE-2008-0657).
  
Impact :

    A remote attacker could entice a user to run a specially crafted applet
    on a website or start an application in Java Web Start to execute
    arbitrary code outside of the Java sandbox and of the Java security
    restrictions with the privileges of the user running Java. The attacker
    could also obtain sensitive information, create, modify, rename and
    read local files, execute local applications, establish connections in
    the local network, bypass the same origin policy, and cause a Denial of
    Service via multiple vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200705-23.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200706-08.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sun JRE 1.6 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.05'
    All Sun JRE 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.5.0.15'
    All Sun JRE 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.4.2.17'
    All Sun JDK 1.6 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.05'
    All Sun JDK 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.5.0.15'
    All Sun JDK 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.4.2.17'
    All emul-linux-x86-java 1.6 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.6.0.05'
    All emul-linux-x86-java 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.5.0.15'
    All emul-linux-x86-java 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.4.2.17'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("ge 1.6.0.05", "rge 1.5.0.21", "rge 1.5.0.20", "rge 1.5.0.19", "rge 1.5.0.18", "rge 1.5.0.17", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.4.2.17", "rge 1.5.0.22"), vulnerable:make_list("lt 1.6.0.05"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("ge 1.6.0.05", "rge 1.5.0.21", "rge 1.5.0.20", "rge 1.5.0.19", "rge 1.5.0.18", "rge 1.5.0.17", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.4.2.17", "rge 1.5.0.22"), vulnerable:make_list("lt 1.6.0.05"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("ge 1.6.0.05", "rge 1.5.0.21", "rge 1.5.0.20", "rge 1.5.0.19", "rge 1.5.0.18", "rge 1.5.0.17", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.4.2.17", "rge 1.5.0.22"), vulnerable:make_list("lt 1.6.0.05"))) flag++;

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
