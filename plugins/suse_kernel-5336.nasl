#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5336.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33252);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-5500", "CVE-2007-5904", "CVE-2007-6206", "CVE-2007-6282", "CVE-2007-6712", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669", "CVE-2008-2136", "CVE-2008-2358");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-5336)");
  script_summary(english:"Check for the kernel-5336 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

CVE-2008-1615: On x86_64 a denial of service attack could be used by
local attackers to immediately panic / crash the machine.

CVE-2008-2358: A security problem in DCCP was fixed, which could be
used by remote attackers to crash the machine.

CVE-2007-6206: An information leakage during coredumping of root
processes was fixed.

CVE-2007-6712: A integer overflow in the hrtimer_forward function
(hrtimer.c) in Linux kernel, when running on 64-bit systems, allows
local users to cause a denial of service (infinite loop) via a timer
with a large expiry value, which causes the timer to always be
expired.

CVE-2008-2136: A problem in SIT IPv6 tunnel handling could be used by
remote attackers to immediately crash the machine.

CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk could
potentially allow local attackers to execute code by timing file
locking.

CVE-2008-1367: Clear the 'direction' flag before calling signal
handlers. For specific not yet identified programs under specific
timing conditions this could potentially have caused memory corruption
or code execution.

CVE-2008-1375: Fixed a dnotify race condition, which could be used by
local attackers to potentially execute code.

CVE-2007-6282: A remote attacker could crash the IPSec/IPv6 stack by
sending a bad ESP packet. This requires the host to be able to receive
such packets (default filtered by the firewall).

CVE-2007-5500: A ptrace bug could be used by local attackers to hang
their own processes indefinitely.

CVE-2007-5904: A remote buffer overflow in CIFS was fixed which could
be used by remote attackers to crash the machine or potentially
execute code.

And the following bugs (numbers are https://bugzilla.novell.com/
references) :

  - patches.arch/x86-nosmp-implies-noapic.patch: When
    booting with nosmp or maxcpus=0 on i386 or x86-64, we
    must disable the I/O APIC, otherwise the system won't
    boot in most cases (bnc#308540).

  - patches.arch/i386-at-sysinfo-ehdr: i386: make
    AT_SYSINFO_EHDR consistent with AT_SYSINFO (bnc#289641).

  - patches.suse/bonding-workqueue: Update to fix a hang
    when closing a bonding device (342994).

  - patches.fixes/mptspi-dv-renegotiate-oops: mptlinux
    crashes on kernel 2.6.22 (bnc#271749)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 94, 119, 189, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-kdump-2.6.18.8-0.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.10") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-default / kernel-kdump / kernel-source / etc");
}
