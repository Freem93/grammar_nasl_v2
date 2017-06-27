#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14535);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0109", "CVE-2004-0133", "CVE-2004-0177", "CVE-2004-0178", "CVE-2004-0181", "CVE-2004-0228", "CVE-2004-0229", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0495", "CVE-2004-0535", "CVE-2004-0554", "CVE-2004-1983");
  script_osvdb_id(5362, 5363, 5364, 5397, 5398, 5667, 5697, 5799, 7077, 7218, 7219, 7423);
  script_xref(name:"GLSA", value:"200407-02");

  script_name(english:"GLSA-200407-02 : Linux Kernel: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200407-02
(Linux Kernel: Multiple vulnerabilities)

    Multiple flaws have been discovered in the Linux kernel. This advisory
    corrects the following issues:
    CAN-2004-0109: This vulnerability allows privilege escalation using
    ISO9660 file systems through a buffer overflow via a malformed file
    system containing a long symbolic link entry. This can allow arbitrary
    code execution at kernel level.
    CAN-2004-0133: The XFS file system in 2.4 series kernels has an
    information leak by which data in the memory can be written to the
    device hosting the file system, allowing users to obtain portions of
    kernel memory by reading the raw block device.
    CAN-2004-0177: The ext3 file system in 2.4 series kernels does not
    properly initialize journal descriptor blocks, causing an information
    leak by which data in the memory can be written to the device hosting
    the file system, allowing users to obtain portions of kernel memory by
    reading the raw device.
    CAN-2004-0181: The JFS file system in 2.4 series kernels has an
    information leak by which data in the memory can be written to the
    device hosting the file system, allowing users to obtain portions of
    kernel memory by reading the raw device.
    CAN-2004-0178: The OSS Sound Blaster [R] Driver has a Denial of Service
    vulnerability since it does not handle certain sample sizes properly.
    This allows local users to hang the kernel.
    CAN-2004-0228: Due to an integer signedness error in the CPUFreq /proc
    handler code in 2.6 series Linux kernels, local users can escalate
    their privileges.
    CAN-2004-0229: The framebuffer driver in 2.6 series kernel drivers does
    not use the fb_copy_cmap method of copying structures. The impact of
    this issue is unknown, however.
    CAN-2004-0394: A buffer overflow in the panic() function of 2.4 series
    Linux kernels exists, but it may not be exploitable under normal
    circumstances due to its functionality.
    CAN-2004-0427: The do_fork() function in both 2.4 and 2.6 series Linux
    kernels does not properly decrement the mm_count counter when an error
    occurs, triggering a memory leak that allows local users to cause a
    Denial of Service by exhausting other applications of memory; causing
    the kernel to panic or to kill services.
    CAN-2004-0495: Multiple vulnerabilities found by the Sparse source
    checker in the kernel allow local users to escalate their privileges or
    gain access to kernel memory.
    CAN-2004-0535: The e1000 NIC driver does not properly initialize memory
    structures before using them, allowing users to read kernel memory.
    CAN-2004-0554: 2.4 and 2.6 series kernels running on an x86 or an AMD64
    architecture allow local users to cause a Denial of Service by a total
    system hang, due to an infinite loop that triggers a signal handler
    with a certain sequence of fsave and frstor instructions.
    Local DoS in PaX: If ASLR is enabled as a GRSecurity PaX feature, a
    Denial of Service can be achieved by putting the kernel into an
    infinite loop. Only 2.6 series GRSecurity kernels are affected by this
    issue.
    RSBAC 1.2.3 JAIL issues: A flaw in the RSBAC JAIL implementation allows
    suid/sgid files to be created inside the jail since the relevant module
    does not check the corresponding mode values. This can allow privilege
    escalation inside the jail. Only rsbac-(dev-)sources are affected by
    this issue.
  
Impact :

    Arbitrary code with normal non-super-user privileges may be able to
    exploit any of these vulnerabilities; gaining kernel level access to
    memory structures and hardware devices. This may be used for further
    exploitation of the system, to leak sensitive data or to cause a Denial
    of Service on the affected kernel.
  
Workaround :

    Although users may not be affected by certain vulnerabilities, all
    kernels are affected by the CAN-2004-0394, CAN-2004-0427 and
    CAN-2004-0554 issues which have no workaround. As a result, all users
    are urged to upgrade their kernels to patched versions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are encouraged to upgrade to the latest available sources for
    their system:
    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ia64-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mm-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openmosix-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pac-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pegasos-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pegasos-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:planet-ccrma-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc64-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsbac-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsbac-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:selinux-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sparc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:uclinux-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermode-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vanilla-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vserver-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:win4lin-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wolk-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xbox-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xfs-sources");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"sys-kernel/rsbac-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-dev-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-sources", unaffected:make_list("ge 2.4.26_p6"), vulnerable:make_list("lt 2.4.26_p6"))) flag++;
if (qpkg_check(package:"sys-kernel/planet-ccrma-sources", unaffected:make_list("ge 2.4.21-r10"), vulnerable:make_list("lt 2.4.21-r10"))) flag++;
if (qpkg_check(package:"sys-kernel/openmosix-sources", unaffected:make_list("ge 2.4.22-r10"), vulnerable:make_list("lt 2.4.22-r10"))) flag++;
if (qpkg_check(package:"sys-kernel/vserver-sources", unaffected:make_list("ge 2.0"), vulnerable:make_list("lt 2.0", "ge 2.4", "lt 2.4.26.1.3.9-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/development-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/xbox-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-dev-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/compaq-sources", unaffected:make_list("ge 2.4.9.32.7-r7"), vulnerable:make_list("lt 2.4.9.32.7-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/pegasos-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/grsec-sources", unaffected:make_list("ge 2.4.26.2.0-r5"), vulnerable:make_list("lt 2.4.26.2.0-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/uclinux-sources", unaffected:make_list("ge 2.4.26_p0-r2"), vulnerable:make_list("lt 2.4.26_p0-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/gaming-sources", unaffected:make_list("ge 2.4.20-r14"), vulnerable:make_list("lt 2.4.20-r14"))) flag++;
if (qpkg_check(package:"sys-kernel/wolk-sources", unaffected:make_list("rge 4.9-r9", "rge 4.11-r6", "ge 4.14-r3"), vulnerable:make_list("lt 4.14-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-sources", unaffected:make_list("ge 2.4.27"), vulnerable:make_list("le 2.4.26"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-sources", unaffected:make_list("rge 2.4.19-r17", "rge 2.4.20-r20", "rge 2.4.22-r12", "rge 2.4.25-r5", "ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/aa-sources", unaffected:make_list("eq 2.4.23-r2"), vulnerable:make_list("lt 2.4.23-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/gs-sources", unaffected:make_list("ge 2.4.25_pre7-r7"), vulnerable:make_list("lt 2.4.25_pre7-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/ia64-sources", unaffected:make_list("ge 2.4.24-r5"), vulnerable:make_list("lt 2.4.24-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc64-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/pegasos-dev-sources", unaffected:make_list("ge 2.6.7"), vulnerable:make_list("lt 2.6.7"))) flag++;
if (qpkg_check(package:"sys-kernel/pac-sources", unaffected:make_list("ge 2.4.23-r8"), vulnerable:make_list("lt 2.4.23-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/alpha-sources", unaffected:make_list("ge 2.4.21-r8"), vulnerable:make_list("lt 2.4.21-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/xfs-sources", unaffected:make_list("ge 2.4.24-r8"), vulnerable:make_list("lt 2.4.24-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/rsbac-dev-sources", unaffected:make_list("ge 2.6.7-r1"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/selinux-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/usermode-sources", unaffected:make_list("rge 2.4.24-r5", "ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", unaffected:make_list("eq 2.4.26-r1", "ge 2.6.7-r1"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/win4lin-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/mm-sources", unaffected:make_list("ge 2.6.7-r1"), vulnerable:make_list("lt 2.6.7-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Linux Kernel");
}
