#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5751.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34755);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2007-6716", "CVE-2008-1673", "CVE-2008-2812", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3525", "CVE-2008-3527", "CVE-2008-3528", "CVE-2008-3833", "CVE-2008-4210", "CVE-2008-4302", "CVE-2008-4576");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-5751)");
  script_summary(english:"Check for the kernel-5751 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes various bugs and also several security 
issues :

CVE-2008-4576: Fixed a crash in SCTP INIT-ACK, on mismatch between
SCTP AUTH availability. This might be exploited remotely for a denial
of service (crash) attack.

CVE-2008-3833: The generic_file_splice_write function in fs/splice.c
in the Linux kernel does not properly strip setuid and setgid bits
when there is a write to a file, which allows local users to gain the
privileges of a different group, and obtain sensitive information or
possibly have unspecified other impact, by splicing into an inode in
order to create an executable file in a setgid directory.

CVE-2008-4210: fs/open.c in the Linux kernel before 2.6.22 does not
properly strip setuid and setgid bits when there is a write to a file,
which allows local users to gain the privileges of a different group,
and obtain sensitive information or possibly have unspecified other
impact, by creating an executable file in a setgid directory through
the (1) truncate or (2) ftruncate function in conjunction with
memory-mapped I/O.

CVE-2008-4302: fs/splice.c in the splice subsystem in the Linux kernel
before 2.6.22.2 does not properly handle a failure of the
add_to_page_cache_lru function, and subsequently attempts to unlock a
page that was not locked, which allows local users to cause a denial
of service (kernel BUG and system crash), as demonstrated by the fio
I/O tool.

CVE-2008-3528: The ext[234] filesystem code fails to properly handle
corrupted data structures. With a mounted filesystem image or
partition that have corrupted dir->i_size and dir->i_blocks, a user
performing either a read or write operation on the mounted image or
partition can lead to a possible denial of service by spamming the
logfile.

CVE-2007-6716: fs/direct-io.c in the dio subsystem in the Linux kernel
did not properly zero out the dio struct, which allows local users to
cause a denial of service (OOPS), as demonstrated by a certain fio
test.

CVE-2008-3525: Added missing capability checks in sbni_ioctl().

CVE-2008-3272: Fixed range checking in the snd_seq OSS ioctl, which
could be used to leak information from the kernel.

CVE-2008-2931: The do_change_type function in fs/namespace.c did not
verify that the caller has the CAP_SYS_ADMIN capability, which allows
local users to gain privileges or cause a denial of service by
modifying the properties of a mountpoint.

CVE-2008-2812: Various NULL ptr checks have been added to tty op
functions, which might have been used by local attackers to execute
code. We think that this affects only devices openable by root, so the
impact is limited.

CVE-2008-1673: Added range checking in ASN.1 handling for the CIFS and
SNMP NAT netfilter modules.

CVE-2008-3527: arch/i386/kernel/sysenter.c in the Virtual Dynamic
Shared Objects (vDSO) implementation in the Linux kernel before 2.6.21
did not properly check boundaries, which allows local users to gain
privileges or cause a denial of service via unspecified vectors,
related to the install_special_mapping, syscall, and syscall32_nopage
functions."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/12");
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

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-kdump-2.6.18.8-0.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.13") ) flag++;

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
