#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200707-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25665);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:54 $");

  script_cve_id("CVE-2007-3508");
  script_osvdb_id(37901);
  script_xref(name:"GLSA", value:"200707-04");

  script_name(english:"GLSA-200707-04 : GNU C Library: Integer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200707-04
(GNU C Library: Integer overflow)

    Tavis Ormandy of the Gentoo Linux Security Team discovered a flaw in
    the handling of the hardware capabilities mask by the dynamic loader.
    If a mask is specified with a high population count, an integer
    overflow could occur when allocating memory.
  
Impact :

    As the hardware capabilities mask is honored by the dynamic loader
    during the execution of suid and sgid programs, in theory this
    vulnerability could result in the execution of arbitrary code with root
    privileges. This update is provided as a precaution against currently
    unknown attack vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200707-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-libs/glibc-2.5-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86)$") audit(AUDIT_ARCH_NOT, "x86", ourarch);

flag = 0;

if (qpkg_check(package:"sys-libs/glibc", arch:"x86", unaffected:make_list("ge 2.5-r4"), vulnerable:make_list("lt 2.5-r4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU C Library");
}
