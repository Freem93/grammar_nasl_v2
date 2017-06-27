#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201604-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(90380);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3497", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-6030", "CVE-2012-6031", "CVE-2012-6032", "CVE-2012-6033", "CVE-2012-6034", "CVE-2012-6035", "CVE-2012-6036", "CVE-2015-2151", "CVE-2015-3209", "CVE-2015-3259", "CVE-2015-3340", "CVE-2015-3456", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164", "CVE-2015-5154", "CVE-2015-7311", "CVE-2015-7504", "CVE-2015-7812", "CVE-2015-7813", "CVE-2015-7814", "CVE-2015-7835", "CVE-2015-7871", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8554", "CVE-2015-8555", "CVE-2016-2270", "CVE-2016-2271");
  script_xref(name:"GLSA", value:"201604-03");

  script_name(english:"GLSA-201604-03 : Xen: Multiple vulnerabilities (Venom)");
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
"The remote host is affected by the vulnerability described in GLSA-201604-03
(Xen: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Xen. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A local attacker could possibly cause a Denial of Service condition or
      obtain sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201604-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xen 4.5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.5.2-r5'
    All Xen 4.6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.6.0-r9'
    All Xen tools 4.5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-tools-4.5.2-r5'
    All Xen tools 4.6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-tools-4.6.0-r9'
    All Xen pvgrub users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-pvgrub-4.6.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pvgrub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-pvgrub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/xen", unaffected:make_list("ge 4.6.0-r9", "rge 4.5.2-r5"), vulnerable:make_list("lt 4.6.0-r9"))) flag++;
if (qpkg_check(package:"app-emulation/xen-pvgrub", unaffected:make_list(), vulnerable:make_list("lt 4.6.0"))) flag++;
if (qpkg_check(package:"app-emulation/xen-tools", unaffected:make_list("ge 4.6.0-r9", "rge 4.5.2-r5"), vulnerable:make_list("lt 4.6.0-r9"))) flag++;
if (qpkg_check(package:"app-emulation/pvgrub", unaffected:make_list("ge 4.6.0", "rge 4.5.2"), vulnerable:make_list())) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
