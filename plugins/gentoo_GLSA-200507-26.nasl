#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-26.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19328);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1852");
  script_osvdb_id(18124);
  script_xref(name:"GLSA", value:"200507-26");

  script_name(english:"GLSA-200507-26 : GNU Gadu, CenterICQ, Kadu, EKG, libgadu: Remote code execution in Gadu library");
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
"The remote host is affected by the vulnerability described in GLSA-200507-26
(GNU Gadu, CenterICQ, Kadu, EKG, libgadu: Remote code execution in Gadu library)

    GNU Gadu, CenterICQ, Kadu, EKG and libgadu are vulnerable to an integer
    overflow.
  
Impact :

    A remote attacker could exploit the integer overflow to execute
    arbitrary code or cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/406026/30/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Gadu users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/gnugadu-2.2.6-r1'
    All Kadu users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/kadu-0.4.1'
    All EKG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/ekg-1.6_rc3'
    All libgadu users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/libgadu-20050719'
    All CenterICQ users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/centericq-4.20.0-r3'
    CenterICQ is no longer distributed with Gadu Gadu support, affected
    users are encouraged to migrate to an alternative package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:centericq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ekg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnugadu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kadu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libgadu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
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

if (qpkg_check(package:"net-im/centericq", unaffected:make_list("ge 4.20.0-r3"), vulnerable:make_list("lt 4.20.0-r3"))) flag++;
if (qpkg_check(package:"net-im/kadu", unaffected:make_list("ge 0.4.1"), vulnerable:make_list("lt 0.4.1"))) flag++;
if (qpkg_check(package:"net-im/ekg", unaffected:make_list("ge 1.6_rc3"), vulnerable:make_list("lt 1.6_rc3"))) flag++;
if (qpkg_check(package:"net-im/gnugadu", unaffected:make_list("ge 2.2.6-r1"), vulnerable:make_list("lt 2.2.6-r1"))) flag++;
if (qpkg_check(package:"net-libs/libgadu", unaffected:make_list("ge 1.7.0_pre20050719"), vulnerable:make_list("lt 1.7.0_pre20050719"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU Gadu / CenterICQ / Kadu / EKG / libgadu");
}
