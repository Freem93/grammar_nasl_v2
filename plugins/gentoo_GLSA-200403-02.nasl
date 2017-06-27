#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14453);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0077");
  script_osvdb_id(3986);
  script_xref(name:"GLSA", value:"200403-02");

  script_name(english:"GLSA-200403-02 : Linux kernel do_mremap local privilege escalation vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200403-02
(Linux kernel do_mremap local privilege escalation vulnerability)

    The memory subsystem allows for shrinking, growing, and moving of
    chunks of memory along any of the allocated memory areas which the
    kernel possesses.
    To accomplish this, the do_mremap code calls the do_munmap() kernel
    function to remove any old memory mappings in the new location - but,
    the code doesn't check the return value of the do_munmap() function
    which may fail if the maximum number of available virtual memory area
    descriptors has been exceeded.
    Due to the missing return value check after trying to unmap the middle
    of the first memory area, the corresponding page table entries from the
    second new area are inserted into the page table locations described by
    the first old one, thus they are subject to page protection flags of
    the first area. As a result, arbitrary code can be executed.
  
Impact :

    Arbitrary code with normal non-super-user privileges may be able to
    exploit this vulnerability and may disrupt the operation of other parts
    of the kernel memory management subroutines finally leading to
    unexpected behavior.
    Since no special privileges are required to use the mremap() and
    munmap() system calls any process may misuse this unexpected behavior
    to disrupt the kernel memory management subsystem. Proper exploitation
    of this vulnerability may lead to local privilege escalation allowing
    for the execution of arbitrary code with kernel level root access.
    Proof-of-concept exploit code has been created and successfully tested,
    permitting root escalation on vulnerable systems. As a result, all
    users should upgrade their kernels to new or patched versions.
  
Workaround :

    Users who are unable to upgrade their kernels may attempt to use
    'sysctl -w vm.max_map_count=1000000', however, this is a temporary fix
    which only solves the problem by increasing the number of memory areas
    that can be created by each process. Because of the static nature of
    this workaround, it is not recommended and users are urged to upgrade
    their systems to the latest available patched sources."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-02"
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
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:alpha-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ck-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:compaq-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gaming-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:grsec-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gs-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ia64-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-prepatch-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mm-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openmosix-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pac-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:planet-ccrma-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources-benh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources-dev");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/18");
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

if (qpkg_check(package:"sys-kernel/hppa-dev-sources", unaffected:make_list("ge 2.6.2_p3-r1"), vulnerable:make_list("lt 2.6.2_p3-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-sources", unaffected:make_list("ge 2.4.24_p0-r1"), vulnerable:make_list("lt 2.4.24_p0-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/planet-ccrma-sources", unaffected:make_list("ge 2.4.21-r5"), vulnerable:make_list("lt 2.4.21-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/openmosix-sources", unaffected:make_list("ge 2.4.22-r4"), vulnerable:make_list("lt 2.4.22-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/development-sources", unaffected:make_list("ge 2.6.3_rc1"), vulnerable:make_list("lt 2.6.3_rc1"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources-benh", unaffected:make_list("ge 2.4.22-r5"), vulnerable:make_list("lt 2.4.22-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", unaffected:make_list("ge 2.6.3_rc1"), vulnerable:make_list("lt 2.6.3_rc1"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-prepatch-sources", unaffected:make_list("ge 2.4.25_rc4"), vulnerable:make_list("lt 2.4.25_rc4"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-sources", unaffected:make_list("ge 2.4.25_rc4"), vulnerable:make_list("lt 2.4.25_rc4"))) flag++;
if (qpkg_check(package:"sys-kernel/compaq-sources", unaffected:make_list("ge 2.4.9.32.7-r2"), vulnerable:make_list("lt 2.4.9.32.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources-crypto", unaffected:make_list("ge 2.4.20-r3"), vulnerable:make_list("lt 2.4.20-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/grsec-sources", unaffected:make_list("ge 2.4.24.1.9.13-r1"), vulnerable:make_list("lt 2.4.24.1.9.13-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources-dev", unaffected:make_list("ge 2.4.24-r2"), vulnerable:make_list("lt 2.4.24-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/gaming-sources", unaffected:make_list("ge 2.4.20-r8"), vulnerable:make_list("lt 2.4.20-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/wolk-sources", unaffected:make_list("eq 4.9-r4", "ge 4.10_pre7-r3"), vulnerable:make_list("lt 4.10_pre7-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-sources", unaffected:make_list("ge 2.4.25"), vulnerable:make_list("lt 2.4.25"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-sources", unaffected:make_list("eq 2.4.19-r11", "eq 2.4.20-r12", "ge 2.4.22-r7"), vulnerable:make_list("lt 2.4.22-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-prepatch-sources", unaffected:make_list("ge 2.4.25_pre6-r1"), vulnerable:make_list("lt 2.4.25_pre6-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-sources", unaffected:make_list("ge 2.4.24-r1"), vulnerable:make_list("lt 2.4.24-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/aa-sources", unaffected:make_list("ge 2.4.23-r1"), vulnerable:make_list("lt 2.4.23-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/gs-sources", unaffected:make_list("ge 2.4.25_pre7-r2"), vulnerable:make_list("lt 2.4.25_pre7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/ia64-sources", unaffected:make_list("ge 2.4.24-r1"), vulnerable:make_list("lt 2.4.24-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/pac-sources", unaffected:make_list("ge 2.4.23-r3"), vulnerable:make_list("lt 2.4.23-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-dev-sources", unaffected:make_list("ge 2.6.3_rc1"), vulnerable:make_list("lt 2.6.3_rc1"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-development-sources", unaffected:make_list("ge 2.6.3_rc1-r1"), vulnerable:make_list("lt 2.6.3_rc1-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-sources", unaffected:make_list("ge 2.4.24-r2"), vulnerable:make_list("lt 2.4.24-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/alpha-sources", unaffected:make_list("ge 2.4.21-r4"), vulnerable:make_list("lt 2.4.21-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/xfs-sources", unaffected:make_list("ge 2.4.24-r2"), vulnerable:make_list("lt 2.4.24-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources", unaffected:make_list("ge 2.4.24-r1"), vulnerable:make_list("lt 2.4.24-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/selinux-sources", unaffected:make_list("ge 2.4.24-r2"), vulnerable:make_list("lt 2.4.24-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/usermode-sources", unaffected:make_list("rge 2.4.24-r1", "rge 2.4.26", "ge 2.6.3-r1"), vulnerable:make_list("lt 2.6.3-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", unaffected:make_list("eq 2.4.24-r1", "ge 2.6.2-r1"), vulnerable:make_list("lt 2.6.2-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/win4lin-sources", unaffected:make_list("eq 2.4.23-r2", "ge 2.6.2-r1"), vulnerable:make_list("lt 2.6.2-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/mm-sources", unaffected:make_list("ge 2.6.3_rc1-r1"), vulnerable:make_list("lt 2.6.3_rc1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sys-kernel/hppa-dev-sources / sys-kernel/hppa-sources / etc");
}
