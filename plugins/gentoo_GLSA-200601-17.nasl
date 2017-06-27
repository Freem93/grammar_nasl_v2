#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200601-17.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20829);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");
  script_osvdb_id(22233, 22234, 22235, 22236);
  script_xref(name:"GLSA", value:"200601-17");

  script_name(english:"GLSA-200601-17 : Xpdf, Poppler, GPdf, libextractor, pdftohtml: Heap overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200601-17
(Xpdf, Poppler, GPdf, libextractor, pdftohtml: Heap overflows)

    Chris Evans has reported some integer overflows in Xpdf when
    attempting to calculate buffer sizes for memory allocation, leading to
    a heap overflow and a potential infinite loop when handling malformed
    input files.
  
Impact :

    By sending a specially crafted PDF file to a victim, an attacker
    could cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200601-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/xpdf-3.01-r5'
    All Poppler users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/poppler-0.4.3-r4'
    All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-2.10.0-r3'
    All libextractor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libextractor-0.5.9'
    All pdftohtml users should migrate to the latest stable version
    of Poppler."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libextractor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pdftohtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/03");
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

if (qpkg_check(package:"app-text/gpdf", unaffected:make_list("ge 2.10.0-r3"), vulnerable:make_list("lt 2.10.0-r3"))) flag++;
if (qpkg_check(package:"app-text/poppler", unaffected:make_list("ge 0.4.3-r4"), vulnerable:make_list("lt 0.4.3-r4"))) flag++;
if (qpkg_check(package:"app-text/pdftohtml", unaffected:make_list(), vulnerable:make_list("lt 0.36-r4"))) flag++;
if (qpkg_check(package:"media-libs/libextractor", unaffected:make_list("ge 0.5.9"), vulnerable:make_list("lt 0.5.9"))) flag++;
if (qpkg_check(package:"app-text/xpdf", unaffected:make_list("ge 3.01-r5"), vulnerable:make_list("lt 3.01-r5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xpdf / Poppler / GPdf / libextractor / pdftohtml");
}
