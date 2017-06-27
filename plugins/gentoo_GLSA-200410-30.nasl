#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-30.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15582);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-0888", "CVE-2004-0889");
  script_osvdb_id(11168, 13149);
  script_xref(name:"GLSA", value:"200410-30");

  script_name(english:"GLSA-200410-30 : GPdf, KPDF, KOffice: Vulnerabilities in included xpdf");
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
"The remote host is affected by the vulnerability described in GLSA-200410-30
(GPdf, KPDF, KOffice: Vulnerabilities in included xpdf)

    GPdf, KPDF and KOffice all include xpdf code to handle PDF files. xpdf is
    vulnerable to multiple integer overflows, as described in GLSA 200410-20.
  
Impact :

    An attacker could entice a user to open a specially crafted PDF file,
    potentially resulting in execution of arbitrary code with the rights of the
    user running the affected utility.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200410-20.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-0.132-r2'
    All KDE users should upgrade to the latest version of kdegraphics:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.3.0-r2'
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-1.3.3-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:koffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"kde-base/kdegraphics", unaffected:make_list("ge 3.3.1-r2", "rge 3.3.0-r2", "rge 3.2.3-r2"), vulnerable:make_list("lt 3.3.1-r2"))) flag++;
if (qpkg_check(package:"app-text/gpdf", unaffected:make_list("ge 2.8.0-r2", "rge 0.132-r2"), vulnerable:make_list("lt 2.8.0-r2"))) flag++;
if (qpkg_check(package:"app-office/koffice", unaffected:make_list("ge 1.3.4-r1", "rge 1.3.3-r2"), vulnerable:make_list("lt 1.3.4-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GPdf / KPDF / KOffice");
}
