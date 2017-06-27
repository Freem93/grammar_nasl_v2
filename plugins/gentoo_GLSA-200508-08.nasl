#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19441);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-2097");
  script_osvdb_id(18666, 18667, 18693);
  script_xref(name:"GLSA", value:"200508-08");

  script_name(english:"GLSA-200508-08 : Xpdf, Kpdf, GPdf: Denial of Service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200508-08
(Xpdf, Kpdf, GPdf: Denial of Service vulnerability)

    Xpdf, Kpdf and GPdf do not handle a broken table of embedded
    TrueType fonts correctly. After detecting such a table, Xpdf, Kpdf and
    GPdf attempt to reconstruct the information in it by decoding the PDF
    file, which causes the generation of a huge temporary file.
  
Impact :

    A remote attacker may cause a Denial of Service by creating a
    specially crafted PDF file, sending it to a CUPS printing system (which
    uses Xpdf), or by enticing a user to open it in Xpdf, Kpdf, or GPdf.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/xpdf-3.00-r10'
    All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-2.10.0-r1'
    All Kpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.3.2-r3'
    All KDE Split Ebuild Kpdf users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kpdf-3.4.1-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
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

if (qpkg_check(package:"kde-base/kdegraphics", unaffected:make_list("ge 3.3.2-r3"), vulnerable:make_list("lt 3.3.2-r3"))) flag++;
if (qpkg_check(package:"app-text/gpdf", unaffected:make_list("ge 2.10.0-r1"), vulnerable:make_list("lt 2.10.0-r1"))) flag++;
if (qpkg_check(package:"kde-base/kpdf", unaffected:make_list("ge 3.4.1-r1"), vulnerable:make_list("lt 3.4.1-r1"))) flag++;
if (qpkg_check(package:"app-text/xpdf", unaffected:make_list("ge 3.00-r10"), vulnerable:make_list("lt 3.00-r10"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xpdf / Kpdf / GPdf");
}
