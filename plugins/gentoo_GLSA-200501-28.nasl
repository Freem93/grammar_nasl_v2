#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-28.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16419);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2005-0064");
  script_osvdb_id(13050);
  script_xref(name:"GLSA", value:"200501-28");

  script_name(english:"GLSA-200501-28 : Xpdf, GPdf: Stack overflow in Decrypt::makeFileKey2");
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
"The remote host is affected by the vulnerability described in GLSA-200501-28
(Xpdf, GPdf: Stack overflow in Decrypt::makeFileKey2)

    iDEFENSE reports that the Decrypt::makeFileKey2 function in Xpdf's
    Decrypt.cc insufficiently checks boundaries when processing /Encrypt
    /Length tags in PDF files.
  
Impact :

    An attacker could entice an user to open a specially crafted PDF
    file which would trigger a stack overflow, potentially resulting in
    execution of arbitrary code with the rights of the user running Xpdf or
    GPdf.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.idefense.com/application/poi/display?id=186&type=vulnerabilities&flashstatus=true
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0de7eb8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/xpdf-3.00-r8'
    All GPdf users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-2.8.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/18");
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

if (qpkg_check(package:"app-text/gpdf", unaffected:make_list("ge 2.8.2"), vulnerable:make_list("lt 2.8.2"))) flag++;
if (qpkg_check(package:"app-text/xpdf", unaffected:make_list("ge 3.00-r8"), vulnerable:make_list("le 3.00-r7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xpdf / GPdf: Stack overflow in Decrypt:");
}
