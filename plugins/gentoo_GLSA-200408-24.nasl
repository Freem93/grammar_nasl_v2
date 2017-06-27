#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-24.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14580);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0415", "CVE-2004-0685", "CVE-2004-1058");
  script_osvdb_id(8302, 9273);
  script_xref(name:"GLSA", value:"200408-24");

  script_name(english:"GLSA-200408-24 : Linux Kernel: Multiple information leaks");
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
"The remote host is affected by the vulnerability described in GLSA-200408-24
(Linux Kernel: Multiple information leaks)

    The Linux kernel allows a local attacker to obtain sensitive kernel
    information by gaining access to kernel memory via several leaks in the
    /proc interfaces. These vulnerabilities exist in various drivers which
    make up a working Linux kernel, some of which are present across all
    architectures and configurations.
    CAN-2004-0415 deals with addressing invalid 32 to 64 bit conversions in
    the kernel, as well as insecure direct access to file offset pointers
    in kernel code which can be modified by the open(...), lseek(...) and
    other core system I/O functions by an attacker.
    CAN-2004-0685 deals with certain USB drivers using uninitialized
    structures and then using the copy_to_user(...) kernel call to copy
    these structures. This may leak uninitialized kernel memory, which can
    contain sensitive information from user applications.
    Finally, a race condition with the /proc/.../cmdline node was found,
    allowing environment variables to be read while the process was still
    spawning. If the race is won, environment variables of the process,
    which might not be owned by the attacker, can be read.
  
Impact :

    These vulnerabilities allow a local unprivileged attacker to access
    segments of kernel memory or environment variables which may contain
    sensitive information. Kernel memory may contain passwords, data
    transferred between processes and any memory which applications did not
    clear upon exiting as well as the kernel cache and kernel buffers.
    This information may be used to read sensitive data, open other attack
    vectors for further exploitation or cause a Denial of Service if the
    attacker can gain superuser access via the leaked information.
  
Workaround :

    There is no temporary workaround for any of these information leaks
    other than totally disabling /proc support - otherwise, a kernel
    upgrade is required. A list of unaffected kernels is provided along
    with this announcement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-24"
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
    # # If you use genkernel, run genkernel as you would normally."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:alpha-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ck-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:development-sources");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/04");
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

if (qpkg_check(package:"sys-kernel/rsbac-sources", unaffected:make_list("ge 2.4.26-r5"), vulnerable:make_list("lt 2.4.26-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-dev-sources", unaffected:make_list("ge 2.6.7_p14-r1"), vulnerable:make_list("lt 2.6.7_p14-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-sources", unaffected:make_list("ge 2.4.26_p7-r1"), vulnerable:make_list("lt 2.4.26_p7-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/openmosix-sources", unaffected:make_list("ge 2.4.24-r4"), vulnerable:make_list("lt 2.4.24-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/vserver-sources", unaffected:make_list("ge 2.0"), vulnerable:make_list("lt 2.4.26.1.28-r4", "lt 2.0", "ge 2.4"))) flag++;
if (qpkg_check(package:"sys-kernel/development-sources", unaffected:make_list("ge 2.6.8"), vulnerable:make_list("lt 2.6.8"))) flag++;
if (qpkg_check(package:"sys-kernel/xbox-sources", unaffected:make_list("rge 2.4.27-r1", "ge 2.6.7-r5"), vulnerable:make_list("lt 2.6.7-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-dev-sources", unaffected:make_list("ge 2.6.7-r7"), vulnerable:make_list("lt 2.6.7-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", unaffected:make_list("ge 2.6.7-r12"), vulnerable:make_list("lt 2.6.7-r12"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-sources", unaffected:make_list("rge 2.4.25-r8", "rge 2.4.26-r8", "rge 2.6.4-r8", "rge 2.6.6-r8", "ge 2.6.7-r5"), vulnerable:make_list("lt 2.6.6-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/grsec-sources", unaffected:make_list("ge 2.4.27.2.0.1-r1"), vulnerable:make_list("lt 2.4.27.2.0.1-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/uclinux-sources", unaffected:make_list("rge 2.4.26_p0-r6", "ge 2.6.7_p0-r5"), vulnerable:make_list("lt 2.6.7_p0-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/wolk-sources", unaffected:make_list("rge 4.9-r14", "rge 4.11-r10", "ge 4.14-r7"), vulnerable:make_list("lt 4.14-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-sources", unaffected:make_list("ge 2.4.27"), vulnerable:make_list("lt 2.4.27"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-sources", unaffected:make_list("rge 2.4.19-r22", "rge 2.4.20-r25", "rge 2.4.22-r16", "rge 2.4.25-r9", "ge 2.4.26-r9"), vulnerable:make_list("lt 2.4.26-r9"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-sources", unaffected:make_list("ge 2.4.27-r1"), vulnerable:make_list("lt 2.4.27-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/aa-sources", unaffected:make_list("rge 2.4.23-r2", "ge 2.6.5-r5"), vulnerable:make_list("lt 2.6.5-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/gs-sources", unaffected:make_list("ge 2.4.25_pre7-r11"), vulnerable:make_list("lt 2.4.25_pre7-r11"))) flag++;
if (qpkg_check(package:"sys-kernel/ia64-sources", unaffected:make_list("ge 2.4.24-r10"), vulnerable:make_list("lt 2.4.24-r10"))) flag++;
if (qpkg_check(package:"sys-kernel/pegasos-dev-sources", unaffected:make_list("ge 2.6.8"), vulnerable:make_list("lt 2.6.8"))) flag++;
if (qpkg_check(package:"sys-kernel/pac-sources", unaffected:make_list("ge 2.4.23-r12"), vulnerable:make_list("lt 2.4.23-r12"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-sources", unaffected:make_list("ge 2.4.27-r1"), vulnerable:make_list("lt 2.4.27-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/alpha-sources", unaffected:make_list("ge 2.4.21-r12"), vulnerable:make_list("lt 2.4.21-r12"))) flag++;
if (qpkg_check(package:"sys-kernel/rsbac-dev-sources", unaffected:make_list("ge 2.6.7-r5"), vulnerable:make_list("lt 2.6.7-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/selinux-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/usermode-sources", unaffected:make_list("rge 2.4.24-r9", "rge 2.4.26-r6", "ge 2.6.6-r6"), vulnerable:make_list("lt 2.6.6-r6"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", unaffected:make_list("rge 2.4.26-r1", "ge 2.6.7-r5"), vulnerable:make_list("lt 2.6.7-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/win4lin-sources", unaffected:make_list("rge 2.4.26-r6", "ge 2.6.7-r2"), vulnerable:make_list("lt 2.6.7-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/mm-sources", unaffected:make_list("ge 2.6.8_rc4-r1"), vulnerable:make_list("lt 2.6.8_rc4-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Linux Kernel");
}
