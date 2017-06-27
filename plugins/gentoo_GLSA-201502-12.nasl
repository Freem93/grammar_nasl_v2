#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201502-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(81370);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/13 14:33:57 $");

  script_cve_id("CVE-2014-0429", "CVE-2014-0432", "CVE-2014-0446", "CVE-2014-0448", "CVE-2014-0449", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0463", "CVE-2014-0464", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2409", "CVE-2014-2410", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2420", "CVE-2014-2421", "CVE-2014-2422", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-2428", "CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4208", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4220", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4227", "CVE-2014-4244", "CVE-2014-4247", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4264", "CVE-2014-4265", "CVE-2014-4266", "CVE-2014-4268", "CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6466", "CVE-2014-6468", "CVE-2014-6476", "CVE-2014-6485", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6515", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558", "CVE-2014-6562");
  script_bugtraq_id(66856, 66866, 66870, 66873, 66877, 66879, 66881, 66883, 66886, 66887, 66891, 66893, 66894, 66897, 66898, 66899, 66902, 66903, 66904, 66905, 66907, 66908, 66909, 66910, 66911, 66912, 66913, 66914, 66915, 66916, 66917, 66918, 66919, 66920, 68562, 68571, 68576, 68580, 68583, 68590, 68596, 68599, 68603, 68608, 68612, 68615, 68620, 68624, 68626, 68632, 68636, 68639, 68642, 68645, 70456, 70460, 70468, 70470, 70484, 70488, 70507, 70518, 70519, 70522, 70523, 70531, 70533, 70538, 70544, 70548, 70552, 70556, 70560, 70564, 70565, 70567, 70569, 70570, 70572);
  script_xref(name:"GLSA", value:"201502-12");

  script_name(english:"GLSA-201502-12 : Oracle JRE/JDK: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201502-12
(Oracle JRE/JDK: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Oracle&rsquo;s Java SE
      Development Kit and Runtime Environment. Please review the CVE
      identifiers referenced below for details.
  
Impact :

    A context-dependent attacker may be able to execute arbitrary code,
      disclose, update, insert, or delete certain data.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201502-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JRE 1.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jre-bin-1.7.0.71'
    All Oracle JDK 1.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jdk-bin-1.7.0.71'
    All users of the precompiled 32-bit Oracle JRE should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/emul-linux-x86-java-1.7.0.71'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("ge 1.7.0.71"), vulnerable:make_list("lt 1.7.0.71"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jre-bin", unaffected:make_list("ge 1.7.0.71"), vulnerable:make_list("lt 1.7.0.71"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jdk-bin", unaffected:make_list("ge 1.7.0.71"), vulnerable:make_list("lt 1.7.0.71"))) flag++;

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
