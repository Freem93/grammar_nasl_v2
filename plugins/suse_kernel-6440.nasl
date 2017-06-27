#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-6440.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42009);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2009-0676", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2692");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-6440)");
  script_summary(english:"Check for the kernel-6440 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for openSUSE 10.3 fixes some bugs and several
security problems.

The following security issues are fixed: CVE-2009-2692: A missing NULL
pointer check in the socket sendpage function can be used by local
attackers to gain root privileges.

CVE-2009-2406: A kernel stack overflow when mounting eCryptfs
filesystems in parse_tag_11_packet() was fixed. Code execution might
be possible of ecryptfs is in use.

CVE-2009-2407: A kernel heap overflow when mounting eCryptfs
filesystems in parse_tag_3_packet() was fixed. Code execution might be
possible of ecryptfs is in use.

The compiler option -fno-delete-null-pointer-checks was added to the
kernel build, and the -fwrapv compiler option usage was fixed to be
used everywhere. This works around the compiler removing checks too
aggressively.

CVE-2009-1389: A crash in the r8169 driver when receiving large
packets was fixed. This is probably exploitable only in the local
network.

CVE-2009-0676: A memory disclosure via the SO_BSDCOMPAT socket option
was fixed.

CVE-2009-1630: The nfs_permission function in fs/nfs/dir.c in the NFS
client implementation when atomic_open is available, does not check
execute (aka EXEC or MAY_EXEC) permission bits, which allows local
users to bypass permissions and execute files, as demonstrated by
files on an NFSv4 fileserver.

random: make get_random_int() was made more random to enhance ASLR
protection."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.19-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.19-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.19-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.19-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.19-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.19-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.19-0.4") ) flag++;

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
