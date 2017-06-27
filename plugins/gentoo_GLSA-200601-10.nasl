#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200601-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20731);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3905", "CVE-2005-3906");
  script_bugtraq_id(15615);
  script_osvdb_id(21236, 21237, 21238);
  script_xref(name:"GLSA", value:"200601-10");

  script_name(english:"GLSA-200601-10 : Sun and Blackdown Java: Applet privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200601-10
(Sun and Blackdown Java: Applet privilege escalation)

    Adam Gowdiak discovered multiple vulnerabilities in the Java
    Runtime Environment's Reflection APIs that may allow untrusted applets
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
    value:"http://sunsolve.sun.com/searchproxy/document.do?assetkey=1-26-102003-1"
  );
  # http://www.blackdown.org/java-linux/java2-status/security/Blackdown-SA-2005-03.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6562158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200601-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.4.2.09'
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.4.2.09'
    All Blackdown JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/blackdown-jdk-1.4.2.03'
    All Blackdown JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/blackdown-jre-1.4.2.03'
    Note to SPARC and PPC users: There is no stable secure
    Blackdown Java for the SPARC or PPC architectures. Affected users on
    the PPC architecture should consider switching to the IBM Java packages
    (ibm-jdk-bin and ibm-jre-bin). Affected users on the SPARC should
    remove the package until a SPARC package is released."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/blackdown-jre", unaffected:make_list("ge 1.4.2.03"), vulnerable:make_list("lt 1.4.2.03"))) flag++;
if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("ge 1.4.2.09"), vulnerable:make_list("lt 1.4.2.09"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("ge 1.4.2.09"), vulnerable:make_list("lt 1.4.2.09"))) flag++;
if (qpkg_check(package:"dev-java/blackdown-jdk", unaffected:make_list("ge 1.4.2.03"), vulnerable:make_list("lt 1.4.2.03"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sun and Blackdown Java");
}
