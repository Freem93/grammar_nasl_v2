#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200705-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25187);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352");
  script_osvdb_id(34109, 34110, 34917, 34918);
  script_xref(name:"GLSA", value:"200705-10");

  script_name(english:"GLSA-200705-10 : LibXfont, TightVNC: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200705-10
(LibXfont, TightVNC: Multiple vulnerabilities)

    The libXfont code is prone to several integer overflows, in functions
    ProcXCMiscGetXIDList(), bdfReadCharacters() and FontFileInitTable().
    TightVNC contains a local copy of this code and is also affected.
  
Impact :

    A local attacker could use a specially crafted BDF Font to gain root
    privileges on the vulnerable host.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200705-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libXfont users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/libXfont-1.2.7-r1'
    All TightVNC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/tightvnc-1.2.9-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tightvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
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

if (qpkg_check(package:"x11-libs/libXfont", unaffected:make_list("ge 1.2.7-r1"), vulnerable:make_list("lt 1.2.7-r1"))) flag++;
if (qpkg_check(package:"net-misc/tightvnc", unaffected:make_list("ge 1.2.9-r4"), vulnerable:make_list("lt 1.2.9-r4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibXfont / TightVNC");
}
