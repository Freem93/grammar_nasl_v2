#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-22.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(28261);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_osvdb_id(39541, 39542, 39543);
  script_xref(name:"GLSA", value:"200711-22");

  script_name(english:"GLSA-200711-22 : Poppler, KDE: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200711-22
(Poppler, KDE: User-assisted execution of arbitrary code)

    Alin Rad Pop (Secunia Research) discovered several vulnerabilities in
    the 'Stream.cc' file of Xpdf: An integer overflow in the
    DCTStream::reset() method and a boundary error in the
    CCITTFaxStream::lookChar() method, both leading to heap-based buffer
    overflows (CVE-2007-5392, CVE-2007-5393). He also discovered a boundary
    checking error in the DCTStream::readProgressiveDataUnit() method
    causing memory corruption (CVE-2007-4352). Note: Gentoo's version of
    Xpdf is patched to use the Poppler library, so the update to Poppler
    will also fix Xpdf.
  
Impact :

    By enticing a user to view or process a specially crafted PDF file with
    KWord or KPDF or a Poppler-based program such as Gentoo's viewers Xpdf,
    ePDFView, and Evince or the CUPS printing system, a remote attacker
    could cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Poppler users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/poppler-0.6.1-r1'
    All KPDF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kpdf-3.5.7-r3'
    All KDE Graphics Libraries users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.5.7-r3'
    All KWord users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/kword-1.6.3-r2'
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-1.6.3-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"kde-base/kdegraphics", unaffected:make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable:make_list("lt 3.5.8-r1"))) flag++;
if (qpkg_check(package:"app-text/poppler", unaffected:make_list("ge 0.6.1-r1"), vulnerable:make_list("lt 0.6.1-r1"))) flag++;
if (qpkg_check(package:"kde-base/kpdf", unaffected:make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable:make_list("lt 3.5.8-r1"))) flag++;
if (qpkg_check(package:"app-office/kword", unaffected:make_list("ge 1.6.3-r2"), vulnerable:make_list("lt 1.6.3-r2"))) flag++;
if (qpkg_check(package:"app-office/koffice", unaffected:make_list("ge 1.6.3-r2"), vulnerable:make_list("lt 1.6.3-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Poppler / KDE");
}
