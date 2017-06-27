#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201111-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56724);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4451", "CVE-2010-4452", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4466", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4474", "CVE-2010-4475", "CVE-2010-4476", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0862", "CVE-2011-0863", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0872", "CVE-2011-0873", "CVE-2011-3389", "CVE-2011-3516", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3545", "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549", "CVE-2011-3550", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3555", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560", "CVE-2011-3561");
  script_bugtraq_id(43965, 43971, 43979, 43985, 43988, 43992, 43994, 43999, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44020, 44021, 44023, 44024, 44026, 44027, 44028, 44030, 44032, 44035, 44038, 44040, 46091, 46386, 46387, 46388, 46391, 46393, 46394, 46395, 46397, 46398, 46399, 46400, 46402, 46403, 46404, 46405, 46406, 46407, 46409, 46410, 46411, 48137, 48138, 48139, 48140, 48141, 48142, 48143, 48144, 48145, 48146, 48147, 48148, 48149, 49778, 50211, 50215, 50216, 50218, 50220, 50223, 50224, 50226, 50229, 50231, 50234, 50236, 50237, 50239, 50242, 50243, 50246, 50248, 50250);
  script_osvdb_id(68873, 69033, 69034, 69035, 69036, 69037, 69038, 69039, 69040, 69041, 69042, 69043, 69044, 69045, 69046, 69047, 69048, 69049, 69050, 69051, 69052, 69053, 69055, 69056, 69057, 69058, 69059, 70965, 71193, 71605, 71606, 71607, 71608, 71609, 71610, 71611, 71612, 71613, 71614, 71615, 71616, 71617, 71618, 71619, 71620, 71621, 71622, 71623, 73069, 73070, 73071, 73073, 73074, 73075, 73076, 73077, 73081, 73082, 73083, 73084, 73085, 73176, 74829, 76495, 76496, 76497, 76498, 76499, 76500, 76501, 76502, 76503, 76504, 76505, 76506, 76507, 76508, 76509, 76510, 76511, 76512, 76513);
  script_xref(name:"GLSA", value:"201111-02");

  script_name(english:"GLSA-201111-02 : Oracle JRE/JDK: Multiple vulnerabilities (BEAST)");
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
"The remote host is affected by the vulnerability described in GLSA-201111-02
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
    value:"https://security.gentoo.org/glsa/201111-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JDK 1.6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.29'
    All Oracle JRE 1.6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.29'
    All users of the precompiled 32-bit Oracle JRE 1.6 should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/emul-linux-x86-java-1.6.0.29'
    NOTE: As Oracle has revoked the DLJ license for its Java implementation,
      the packages can no longer be updated automatically. This limitation is
      not present on a non-fetch restricted implementation such as
      dev-java/icedtea-bin."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("ge 1.6.0.29"), vulnerable:make_list("lt 1.6.0.29"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("ge 1.6.0.29"), vulnerable:make_list("lt 1.6.0.29"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("ge 1.6.0.29"), vulnerable:make_list("lt 1.6.0.29"))) flag++;

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
