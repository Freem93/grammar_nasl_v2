#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200401-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14441);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_xref(name:"GLSA", value:"200401-01");

  script_name(english:"GLSA-200401-01 : Linux kernel do_mremap() local privilege escalation vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200401-01
(Linux kernel do_mremap() local privilege escalation vulnerability)

    The memory subsystem allows for shrinking, growing, and moving of
    chunks of memory along any of the allocated memory areas which the kernel
    possesses.
    A typical virtual memory area covers at least one memory page. An incorrect
    bound check discovered inside the do_mremap() kernel code performing
    remapping of a virtual memory area may lead to creation of a virtual memory
    area of 0 bytes length.
    The problem is based on the general mremap flaw that remapping 2 pages from
    inside a VMA creates a memory hole of only one page in length but an
    additional VMA of two pages. In the case of a zero sized remapping request
    no VMA hole is created but an additional VMA descriptor of 0
    bytes in length is created.
    This advisory also addresses an information leak in the Linux RTC system.
  
Impact :

    Arbitrary code may be able to exploit this vulnerability and may
    disrupt the operation of other
    parts of the kernel memory management subroutines finally leading to
    unexpected behavior.
    Since no special privileges are required to use the mremap(2) system call
    any process may misuse its unexpected behavior to disrupt the kernel memory
    management subsystem. Proper exploitation of this vulnerability may lead to
    local privilege escalation including execution of arbitrary code
    with kernel level access.
    Proof-of-concept exploit code has been created and successfully tested,
    permitting root escalation on vulnerable systems. As a result, all users
    should upgrade their kernels to new or patched versions.
  
Workaround :

    There is no temporary workaround - a kernel upgrade is required. A list
    of unaffected kernels is provided along with this announcement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0012-mremap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200401-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are encouraged to upgrade to the latest available sources for
    their system:
    $> emerge sync
    $> emerge -pv your-favourite-sources
    $> emerge your-favourite-sources
    $> # Follow usual procedure for compiling and installing a kernel.
    $> # If you use genkernel, run genkernel as you would do normally.
    $> # IF YOUR KERNEL IS MARKED as 'remerge required!' THEN
    $> # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    $> # REPORTS THAT THE SAME VERSION IS INSTALLED."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:alpha-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:arm-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ck-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:compaq-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gaming-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:grsec-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gs-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ia64-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-prepatch-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mm-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openmosix-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pac-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pfeifer-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:planet-ccrma-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources-benh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:selinux-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sparc-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sparc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermode-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vanilla-prepatch-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vanilla-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:win4lin-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wolk-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xfs-sources");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"sys-kernel/hppa-sources", unaffected:make_list("ge 2.4.23_p4-r2"), vulnerable:make_list("lt 2.4.23_p4-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/planet-ccrma-sources", unaffected:make_list("ge 2.4.21-r4"), vulnerable:make_list("lt 2.4.21-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/openmosix-sources", unaffected:make_list("ge 2.4.22-r3"), vulnerable:make_list("lt 2.4.22-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/development-sources", unaffected:make_list("ge 2.6.1_rc3"), vulnerable:make_list("lt 2.6.1_rc3"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources-benh", unaffected:make_list("ge 2.4.22-r4"), vulnerable:make_list("lt 2.4.22-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", unaffected:make_list("ge 2.6.1_rc3"), vulnerable:make_list("lt 2.6.1_rc3"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-prepatch-sources", unaffected:make_list("ge 2.4.25_pre4"), vulnerable:make_list("lt 2.4.25_pre4"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-sources", unaffected:make_list("ge 2.4.23-r2"), vulnerable:make_list("lt 2.4.23-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/compaq-sources", unaffected:make_list("ge 2.4.9.32.7-r1"), vulnerable:make_list("lt 2.4.9.32.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources-crypto", unaffected:make_list("ge 2.4.20-r2"), vulnerable:make_list("lt 2.4.20-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/grsec-sources", unaffected:make_list("gt 2.4.23.2.0_rc4-r1"), vulnerable:make_list("lt 2.4.23.2.0_rc4-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/arm-sources", unaffected:make_list("ge 2.4.19-r2"), vulnerable:make_list("lt 2.4.19-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/gaming-sources", unaffected:make_list("ge 2.4.20-r7"), vulnerable:make_list("lt 2.4.20-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/wolk-sources", unaffected:make_list("ge 4.10_pre7-r2"), vulnerable:make_list("lt 4.10_pre7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/pfeifer-sources", unaffected:make_list("ge 2.4.21.1_pre4-r1"), vulnerable:make_list("lt 2.4.21.1_pre4-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-sources", unaffected:make_list("ge 2.4.24"), vulnerable:make_list("lt 2.4.24"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-sources", unaffected:make_list("gt 2.4.22-r3"), vulnerable:make_list("lt 2.4.22-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-prepatch-sources", unaffected:make_list("ge 2.4.24_pre2-r1"), vulnerable:make_list("lt 2.4.24_pre2-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/aa-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-sources", unaffected:make_list("ge 2.4.22-r2"), vulnerable:make_list("lt 2.4.22-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/gs-sources", unaffected:make_list("ge 2.4.23_pre8-r2"), vulnerable:make_list("lt 2.4.23_pre8-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/ia64-sources", unaffected:make_list("ge 2.4.22-r2"), vulnerable:make_list("lt 2.4.22-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/pac-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-dev-sources", unaffected:make_list("ge 2.6.1_rc2"), vulnerable:make_list("lt 2.6.1_rc2"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-development-sources", unaffected:make_list("ge 2.6.1_rc1-r1"), vulnerable:make_list("lt 2.6.1_rc1-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/alpha-sources", unaffected:make_list("ge 2.4.21-r2"), vulnerable:make_list("lt 2.4.21-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-sources", unaffected:make_list("ge 2.4.24"), vulnerable:make_list("lt 2.4.24"))) flag++;
if (qpkg_check(package:"sys-kernel/xfs-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/selinux-sources", unaffected:make_list("ge 2.4.24"), vulnerable:make_list("lt 2.4.24"))) flag++;
if (qpkg_check(package:"sys-kernel/usermode-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/win4lin-sources", unaffected:make_list("ge 2.6.0-r1"), vulnerable:make_list("lt 2.6.0-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/mm-sources", unaffected:make_list("ge 2.6.1_rc1-r2"), vulnerable:make_list("lt 2.6.1_rc1-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sys-kernel/hppa-sources / sys-kernel/planet-ccrma-sources / etc");
}
