#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-38.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15846);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2004-1029");
  script_osvdb_id(12095);
  script_xref(name:"GLSA", value:"200411-38");

  script_name(english:"GLSA-200411-38 : Sun and Blackdown Java: Applet privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200411-38
(Sun and Blackdown Java: Applet privilege escalation)

    All Java plug-ins are subject to a vulnerability allowing unrestricted
    Java package access.
  
Impact :

    A remote attacker could embed a malicious Java applet in a web page and
    entice a victim to view it. This applet can then bypass security
    restrictions and execute any command or access any file with the rights
    of the user running the web browser.
  
Workaround :

    As a workaround you could disable Java applets on your web browser."
  );
  # http://www.idefense.com/application/poi/display?id=158&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80b885e4"
  );
  # http://www.blackdown.org/java-linux/java2-status/security/Blackdown-SA-2004-01.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c087cc6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-38"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.4.2.06'
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.4.2.06'
    All Blackdown JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/blackdown-jdk-1.4.2.01'
    All Blackdown JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/blackdown-jre-1.4.2.01'
    Note: You should unmerge all vulnerable versions to be fully protected."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(amd64|x86)$") audit(AUDIT_ARCH_NOT, "amd64|x86", ourarch);

flag = 0;

if (qpkg_check(package:"dev-java/blackdown-jre", arch:"x86 amd64", unaffected:make_list("ge 1.4.2.01"), vulnerable:make_list("lt 1.4.2.01"))) flag++;
if (qpkg_check(package:"dev-java/sun-jre-bin", arch:"x86 amd64", unaffected:make_list("ge 1.4.2.06"), vulnerable:make_list("lt 1.4.2.06"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", arch:"x86 amd64", unaffected:make_list("ge 1.4.2.06"), vulnerable:make_list("lt 1.4.2.06"))) flag++;
if (qpkg_check(package:"dev-java/blackdown-jdk", arch:"x86 amd64", unaffected:make_list("ge 1.4.2.01"), vulnerable:make_list("lt 1.4.2.01"))) flag++;

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
