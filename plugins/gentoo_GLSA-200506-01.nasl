#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18406);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1704");
  script_osvdb_id(16757);
  script_xref(name:"GLSA", value:"200506-01");

  script_name(english:"GLSA-200506-01 : Binutils, elfutils: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200506-01
(Binutils, elfutils: Buffer overflow)

    Tavis Ormandy and Ned Ludd of the Gentoo Linux Security Audit Team
    discovered an integer overflow in the BFD library and elfutils,
    resulting in a heap based buffer overflow.
  
Impact :

    Successful exploitation would require a user to access a specially
    crafted binary file, resulting in the execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Binutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose sys-devel/binutils
    All elfutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/elfutils-0.108'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/20");
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

if (qpkg_check(package:"sys-devel/binutils", unaffected:make_list("rge 2.14.90.0.8-r3", "rge 2.15.90.0.1.1-r5", "rge 2.15.90.0.3-r5", "rge 2.15.91.0.2-r2", "rge 2.15.92.0.2-r10", "ge 2.16-r1"), vulnerable:make_list("lt 2.16-r1"))) flag++;
if (qpkg_check(package:"dev-libs/elfutils", unaffected:make_list("ge 0.108"), vulnerable:make_list("lt 0.108"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Binutils / elfutils");
}
