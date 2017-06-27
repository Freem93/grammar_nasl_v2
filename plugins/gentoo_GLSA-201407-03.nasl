#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201407-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(76544);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/13 14:27:08 $");

  script_cve_id("CVE-2013-1442", "CVE-2013-4329", "CVE-2013-4355", "CVE-2013-4356", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4416", "CVE-2013-4494", "CVE-2013-4551", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6375", "CVE-2013-6400", "CVE-2013-6885", "CVE-2014-1642", "CVE-2014-1666", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1895", "CVE-2014-1896", "CVE-2014-2599", "CVE-2014-3124", "CVE-2014-4021");
  script_bugtraq_id(62307, 62630, 62708, 62709, 62710, 62930, 62931, 62932, 62934, 62935, 63404, 63494, 63625, 63830, 63931, 63933, 63983, 64195, 65097, 65125, 65414, 65419, 65424, 66407, 67113, 68070);
  script_xref(name:"GLSA", value:"201407-03");

  script_name(english:"GLSA-201407-03 : Xen: Multiple Vunlerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201407-03
(Xen: Multiple Vunlerabilities)

    Multiple vulnerabilities have been discovered in Xen. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker can utilize multiple vectors to execute arbitrary
      code, cause Denial of Service, or gain access to data on the host.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201407-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xen 4.3 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulations/xen-4.3.2-r2'
    All Xen 4.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulations/xen-4.2.4-r2'
    All xen-tools 4.3 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulations/xen-tools-4.3.2-r2'
    All xen-tools 4.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulations/xen-tools-4.2.4-r2'
    All Xen PVGRUB 4.3 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulations/xen-pvgrub-4.3.2'
    All Xen PVGRUB 4.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulations/xen-pvgrub-4.2.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-pvgrub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulations/xen", unaffected:make_list("ge 4.3.2-r4", "rge 4.2.4-r4"), vulnerable:make_list("lt 4.3.2-r4"))) flag++;
if (qpkg_check(package:"app-emulations/xen-tools", unaffected:make_list("ge 4.3.2-r5", "rge 4.2.4-r6"), vulnerable:make_list("lt 4.3.2-r5"))) flag++;
if (qpkg_check(package:"app-emulations/xen-pvgrub", unaffected:make_list("rge 4.3.2", "rge 4.2.4"), vulnerable:make_list("lt 4.3.2"))) flag++;

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
