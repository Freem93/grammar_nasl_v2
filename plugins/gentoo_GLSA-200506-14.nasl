#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18529);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_osvdb_id(17340);
  script_xref(name:"GLSA", value:"200506-14");

  script_name(english:"GLSA-200506-14 : Sun and Blackdown Java: Applet privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200506-14
(Sun and Blackdown Java: Applet privilege escalation)

    Both Sun's and Blackdown's JDK and JRE may allow untrusted applets
    to elevate privileges.
  
Impact :

    A remote attacker could embed a malicious Java applet in a web
    page and entice a victim to view it. This applet can then bypass
    security restrictions and execute any command or access any file with
    the rights of the user running the web browser.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1"
  );
  # http://www.blackdown.org/java-linux/java2-status/security/Blackdown-SA-2005-02.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?476d4cb9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.4.2.08'
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.4.2.08'
    All Blackdown JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/blackdown-jdk-1.4.2.02'
    All Blackdown JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/blackdown-jre-1.4.2.02'
    Note to SPARC users: There is no stable secure Blackdown Java
    for the SPARC architecture. Affected users should remove the package
    until a SPARC package is released."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/blackdown-jre", unaffected:make_list("ge 1.4.2.02"), vulnerable:make_list("lt 1.4.2.02"))) flag++;
if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("ge 1.4.2.08"), vulnerable:make_list("lt 1.4.2.08"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("ge 1.4.2.08"), vulnerable:make_list("lt 1.4.2.08"))) flag++;
if (qpkg_check(package:"dev-java/blackdown-jdk", unaffected:make_list("ge 1.4.2.02"), vulnerable:make_list("lt 1.4.2.02"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sun and Blackdown Java");
}
