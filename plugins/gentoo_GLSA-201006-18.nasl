#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201006-18.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(46807);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849", "CVE-2010-0850", "CVE-2010-0886", "CVE-2010-0887");
  script_bugtraq_id(39062, 39065, 39067, 39068, 39069, 39070, 39071, 39072, 39073, 39075, 39077, 39078, 39081, 39082, 39083, 39084, 39085, 39086, 39088, 39089, 39090, 39091, 39093, 39094, 39095, 39096, 39492);
  script_osvdb_id(63481, 63482, 63483, 63484, 63485, 63486, 63487, 63488, 63489, 63490, 63491, 63492, 63493, 63494, 63495, 63496, 63497, 63498, 63499, 63500, 63501, 63502, 63503, 63504, 63505, 63506, 63798, 63799);
  script_xref(name:"GLSA", value:"201006-18");

  script_name(english:"GLSA-201006-18 : Oracle JRE/JDK: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201006-18
(Oracle JRE/JDK: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in the Oracle Java
    implementation. Please review the CVE identifiers referenced below and
    the associated Oracle Critical Patch Update Advisory for details.
  
Impact :

    A remote attacker could exploit these vulnerabilities to cause
    unspecified impact, possibly including remote execution of arbitrary
    code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/doc/en/java.xml#doc_chap4"
  );
  # http://www.oracle.com/technology/deploy/security/critical-patch-updates/javacpumar2010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b93c78e2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201006-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JRE 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.20'
    All Oracle JDK 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.20'
    All users of the precompiled 32bit Oracle JRE 1.6.x should upgrade to
    the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.6.0.20'
    All Oracle JRE 1.5.x, Oracle JDK 1.5.x, and precompiled 32bit Oracle
    JRE 1.5.x users are strongly advised to unmerge Java 1.5:
    # emerge --unmerge =app-emulation/emul-linux-x86-java-1.5*
    # emerge --unmerge =dev-java/sun-jre-bin-1.5*
    # emerge --unmerge =dev-java/sun-jdk-1.5*
    Gentoo is ceasing support for the 1.5 generation of the Oracle Java
    Platform in accordance with upstream. All 1.5 JRE versions are masked
    and will be removed shortly. All 1.5 JDK versions are marked as
    'build-only' and will be masked for removal shortly. Users are advised
    to change their default user and system Java implementation to an
    unaffected version. For example:
    # java-config --set-system-vm sun-jdk-1.6
    For more information, please consult the Gentoo Linux Java
    documentation."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("ge 1.6.0.20"), vulnerable:make_list("lt 1.6.0.20"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("ge 1.6.0.20"), vulnerable:make_list("lt 1.6.0.20"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("ge 1.6.0.20"), vulnerable:make_list("lt 1.6.0.20"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle JRE/JDK");
}
