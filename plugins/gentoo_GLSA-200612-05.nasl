#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200612-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(23857);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/13 13:56:52 $");

  script_cve_id("CVE-2006-6120");
  script_xref(name:"GLSA", value:"200612-05");

  script_name(english:"GLSA-200612-05 : KOffice shared libraries: Heap corruption");
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
"The remote host is affected by the vulnerability described in GLSA-200612-05
(KOffice shared libraries: Heap corruption)

    Kees Cook of Ubuntu discovered that 'KLaola::readBigBlockDepot()' in
    klaola.cc fills 'num_of_bbd_blocks' while reading a .ppt (PowerPoint)
    file without proper sanitizing, resulting in an integer overflow
    subsequently overwriting the heap with parts of the file being read.
  
Impact :

    By enticing a user to open a specially crafted PowerPoint file, an
    attacker could crash the application and possibly execute arbitrary
    code with the rights of the user running KOffice.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200612-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All koffice-libs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-libs-1.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/14");
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

if (qpkg_check(package:"app-office/koffice-libs", unaffected:make_list("ge 1.5.0"), vulnerable:make_list("lt 1.5.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "KOffice shared libraries");
}
