#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200710-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(27518);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-3387");
  script_osvdb_id(38120, 40127);
  script_xref(name:"GLSA", value:"200710-20");

  script_name(english:"GLSA-200710-20 : PDFKit, ImageKits: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200710-20
(PDFKit, ImageKits: Buffer overflow)

    Maurycy Prodeus discovered an integer overflow vulnerability possibly
    leading to a stack-based buffer overflow in the XPDF code which PDFKit
    is based on. ImageKits also contains a copy of PDFKit.
  
Impact :

    By enticing a user to view a specially crafted PDF file with a viewer
    based on ImageKits or PDFKit such as Gentoo's ViewPDF, a remote
    attacker could cause an overflow, potentially resulting in the
    execution of arbitrary code with the privileges of the user running the
    application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"PDFKit and ImageKits are not maintained upstream, so the packages were
    masked in Portage. We recommend that users unmerge PDFKit and
    ImageKits:
    # emerge --unmerge gnustep-libs/pdfkit
    # emerge --unmerge gnustep-libs/imagekits
    As an alternative, users should upgrade their systems to use PopplerKit
    instead of PDFKit and Vindaloo instead of ViewPDF."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:imagekits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pdfkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
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

if (qpkg_check(package:"gnustep-libs/imagekits", unaffected:make_list(), vulnerable:make_list("le 0.6"))) flag++;
if (qpkg_check(package:"gnustep-libs/pdfkit", unaffected:make_list(), vulnerable:make_list("le 0.9_pre062906"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PDFKit / ImageKits");
}
