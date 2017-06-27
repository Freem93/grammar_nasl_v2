#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4931.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75555);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1020", "CVE-2011-1160", "CVE-2011-1180", "CVE-2011-1479", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1593", "CVE-2011-2182", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2495", "CVE-2011-2496");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2011:0861-1)");
  script_summary(english:"Check for the kernel-4931 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.3 kernel was updated to 2.6.34.10 to fix various bugs
and security issues.

Following security issues have been fixed: CVE-2011-2495: The
/proc/PID/io interface could be used by local attackers to gain
information on other processes like number of password characters
typed or similar.

CVE-2011-2484: The add_del_listener function in kernel/taskstats.c in
the Linux kernel did not prevent multiple registrations of exit
handlers, which allowed local users to cause a denial of service
(memory and CPU consumption), and bypass the OOM Killer, via a crafted
application.

CVE-2011-2491: A local unprivileged user able to access a NFS
filesystem could use file locking to deadlock parts of an nfs server
under some circumstance.

CVE-2011-2496: The normal mmap paths all avoid creating a mapping
where the pgoff inside the mapping could wrap around due to overflow.
However, an expanding mremap() can take such a non-wrapping mapping
and make it bigger and cause a wrapping condition.

CVE-2011-1017,CVE-2011-2182: The code for evaluating LDM partitions
(in fs/partitions/ldm.c) contained bugs that could crash the kernel
for certain corrupted LDM partitions.

CVE-2011-1479: A regression in inotify fix for a memory leak could
lead to a double free corruption which could crash the system.

CVE-2011-1593: Multiple integer overflows in the next_pidmap function
in kernel/pid.c in the Linux kernel allowed local users to cause a
denial of service (system crash) via a crafted (1) getdents or (2)
readdir system call.

CVE-2011-1020: The proc filesystem implementation in the Linux kernel
did not restrict access to the /proc directory tree of a process after
this process performs an exec of a setuid program, which allowed local
users to obtain sensitive information or cause a denial of service via
open, lseek, read, and write system calls.

CVE-2011-1585: When using a setuid root mount.cifs, local users could
hijack password protected mounted CIFS shares of other local users.

CVE-2011-1160: Kernel information via the TPM devices could by used by
local attackers to read kernel memory.

CVE-2011-1577: The Linux kernel automatically evaluated partition
tables of storage devices. The code for evaluating EFI GUID partitions
(in fs/partitions/efi.c) contained a bug that causes a kernel oops on
certain corrupted GUID partition tables, which might be used by local
attackers to crash the kernel or potentially execute code.

CVE-2011-1180: In the IrDA module, length fields provided by a peer
for names and attributes may be longer than the destination array
sizes and were not checked, this allowed local attackers (close to the
irda port) to potentially corrupt memory.

CVE-2011-1016: The Radeon GPU drivers in the Linux kernel did not
properly validate data related to the AA resolve registers, which
allowed local users to write to arbitrary memory locations associated
with (1) Video RAM (aka VRAM) or (2) the Graphics Translation Table
(GTT) via crafted values.

CVE-2011-1013: A signedness issue in the drm ioctl handling could be
used by local attackers to potentially overflow kernel buffers and
execute code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=595586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=683282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=687113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703155"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-extra-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-vanilla-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-syms-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-base-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-devel-2.6.34.10-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-default-1.1_k2.6.34.10_0.2-19.1.24") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-desktop-1.1_k2.6.34.10_0.2-19.1.24") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
