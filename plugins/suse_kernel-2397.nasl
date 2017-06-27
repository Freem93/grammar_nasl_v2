#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-2397.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27291);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2006-3741", "CVE-2006-4145", "CVE-2006-4538", "CVE-2006-4572", "CVE-2006-4623", "CVE-2006-4997", "CVE-2006-5173", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5648", "CVE-2006-5649", "CVE-2006-5751", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6056", "CVE-2006-6060");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-2397)");
  script_summary(english:"Check for the kernel-2397 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2006-4145: A bug within the UDF filesystem that
    caused machine hangs when truncating files on the
    filesystem was fixed. [#186226]

    - A potential crash when receiving IPX packets was
      fixed. This problem is thought not to be exploitable.
      [#197809]

  - CVE-2006-4623: A problem in DVB packet handling could be
    used to crash the machine when receiving DVB net
    packages is active. [#201429]

  - CVE-2006-3741: A struct file leak was fixed in the
    perfmon(2) system call on the Itanium architecture.
    [#202269]

  - CVE-2006-4538: A malformed ELF image can be used on the
    Itanium architecture to trigger a kernel crash (denial
    of service) when a local attacker can supply it to be
    started. [#203822]

  - CVE-2006-4997: A problem in the ATM protocol handling
    clip_mkip function could be used by remote attackers to
    potentially crash the machine. [#205383]

CVE-2006-5757/

  - CVE-2006-6060: A problem in the grow_buffers function
    could be used to crash or hang the machine using a
    corrupted filesystem. This affects filesystem types
    ISO9660 and NTFS. [#205384]

  - CVE-2006-5173: On the i386 architecture the ELFAGS
    content was not correctly saved, which could be used by
    local attackers to crash other programs using the AC and
    NT flag or to escalate privileges by waiting for iopl
    privileges to be leaked. [#209386]

  - CVE-2006-5174: On the S/390 architecture
    copy_from_user() could be used by local attackers to
    read kernel memory. [#209880]

  - CVE-2006-5619: A problem in IPv6 flowlabel handling can
    be used by local attackers to hang the machine.
    [#216590]

  - CVE-2006-5648: On the PowerPC architecture a syscall has
    been wired without the proper futex implementation that
    can be exploited by a local attacker to hang the
    machine. [#217295]

  - CVE-2006-5649: On the PowerPC architecture the proper
    futex implementation was missing a fix for alignment
    check which could be used by a local attacker to crash
    the machine. [#217295]

  - CVE-2006-5823: A problem in cramfs could be used to
    crash the machine during mounting a crafted cramfs
    image. This requires an attacker to supply such a
    crafted image and have a user mount it. [#218237]

  - CVE-2006-6053: A problem in the ext3 filesystem could be
    used by attackers able to supply a crafted ext3 image to
    cause a denial of service or further data corruption if
    a user mounts this image. [#220288]

  - CVE-2006-6056: Missing return code checking in the HFS
    could be used to crash machine when a user complicit
    attacker is able to supply a specially crafted HFS
    image. [#221230]

  - CVE-2006-4572: Multiple unspecified vulnerabilities in
    netfilter for IPv6 code allow remote attackers to bypass
    intended restrictions via fragmentation attack vectors,
    aka (1) 'ip6_tables protocol bypass bug' and (2)
    'ip6_tables extension header bypass bug'. [#221313]

  - CVE-2006-5751: An integer overflow in the networking
    bridge ioctl starting with Kernel 2.6.7 could be used by
    local attackers to overflow kernel memory buffers and
    potentially escalate privileges [#222656]

Additionaly this kernel catches up to the SLE 10 state of the kernel,
with massive additional fixes."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-um");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mkinitrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:multipath-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"kernel-bigsmp-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-debug-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-default-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-kdump-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-smp-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-source-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-syms-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-um-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-xen-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-xenpae-2.6.16.27-0.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kexec-tools-1.101-32.20") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mkinitrd-1.2-106.25") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"multipath-tools-0.4.6-25.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"open-iscsi-0.5.545-9.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"udev-085-30.16") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-kdump / etc");
}
