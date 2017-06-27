#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200402-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14450);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_xref(name:"GLSA", value:"200402-06");

  script_name(english:"GLSA-200402-06 : Updated kernel packages fix the AMD64 ptrace vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200402-06
(Updated kernel packages fix the AMD64 ptrace vulnerability)

    A vulnerability has been discovered by Andi Kleen in the ptrace emulation
    code for AMD64 platforms when eflags are processed, allowing a local user
    to obtain elevated privileges.  The Common Vulnerabilities and Exposures
    project, http://cve.mitre.org, has assigned CAN-2004-0001 to this issue.
  
Impact :

    Only users of the AMD64 platform are affected: in this scenario, a user may
    be able to obtain elevated privileges, including root access. However, no
    public exploit is known for the vulnerability at this time.
  
Workaround :

    There is no temporary workaround - a kernel upgrade is required. A list of
    unaffected kernels is provided along with this announcement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200402-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are encouraged to upgrade to the latest available sources for
    their system:
    # emerge sync
    # emerge -pv your-favourite-sources
    # emerge your-favourite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.
    # # IF YOUR KERNEL IS MARKED as 'remerge required!' THEN
    # # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    # # REPORTS THAT THE SAME VERSION IS INSTALLED."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ck-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-test-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gs-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vanilla-prepatch-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vanilla-sources");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(amd64)$") audit(AUDIT_ARCH_NOT, "amd64", ourarch);

flag = 0;

if (qpkg_check(package:"sys-kernel/development-sources", arch:"amd64", unaffected:make_list("ge 2.6.2"), vulnerable:make_list("lt 2.6.2"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", arch:"amd64", unaffected:make_list("ge 2.6.2"), vulnerable:make_list("lt 2.6.2"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-prepatch-sources", arch:"amd64", unaffected:make_list("ge 2.4.25_rc3"), vulnerable:make_list("lt 2.4.25_rc3"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-test-sources", arch:"amd64", unaffected:make_list("ge 2.6.2-r1"), vulnerable:make_list("lt 2.6.2"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-sources", arch:"amd64", unaffected:make_list("ge 2.4.24-r1"), vulnerable:make_list("lt 2.4.24-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-sources", arch:"amd64", unaffected:make_list("ge 2.4.22-r6"), vulnerable:make_list("lt 2.4.22-r6"))) flag++;
if (qpkg_check(package:"sys-kernel/gs-sources", arch:"amd64", unaffected:make_list("ge 2.4.25_pre7-r1"), vulnerable:make_list("lt 2.4.25_pre7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", arch:"amd64", unaffected:make_list("ge 2.6.2"), vulnerable:make_list("lt 2.6.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sys-kernel/development-sources / sys-kernel/gentoo-dev-sources / etc");
}
