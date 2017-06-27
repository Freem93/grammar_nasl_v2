#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5700.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34457);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2007-6716", "CVE-2008-1673", "CVE-2008-2812", "CVE-2008-2826", "CVE-2008-3272", "CVE-2008-3276", "CVE-2008-3525", "CVE-2008-3528", "CVE-2008-4576");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-5700)");
  script_summary(english:"Check for the kernel-5700 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 10.3 kernel was update to 2.6.22.19. This includes bugs
and security fixes.

CVE-2008-4576: Fixed a crash in SCTP INIT-ACK, on mismatch between
SCTP AUTH availability. This might be exploited remotely for a denial
of service (crash) attack.

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

CVE-2008-3276: An integer overflow flaw was found in the Linux kernel
dccp_setsockopt_change() function. An attacker may leverage this
vulnerability to trigger a kernel panic on a victim's machine
remotely.

CVE-2008-1673: Added range checking in ASN.1 handling for the CIFS and
SNMP NAT netfilter modules.

CVE-2008-2826: A integer overflow in SCTP was fixed, which might have
been used by remote attackers to crash the machine or potentially
execute code.

CVE-2008-2812: Various NULL ptr checks have been added to tty op
functions, which might have been used by local attackers to execute
code. We think that this affects only devices openable by root, so the
impact is limited."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 264, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/21");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.19-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.19-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.19-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.19-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.19-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.19-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.19-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-source / etc");
}
