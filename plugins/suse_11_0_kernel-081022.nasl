#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-270.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40010);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-3525", "CVE-2008-3526", "CVE-2008-3528", "CVE-2008-3792", "CVE-2008-3911", "CVE-2008-4113", "CVE-2008-4410", "CVE-2008-4445", "CVE-2008-4576");

  script_name(english:"openSUSE Security Update : kernel (kernel-270)");
  script_summary(english:"Check for the kernel-270 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This patch updates the openSUSE 11.0 kernel to the 2.6.25.18 stable
release.

It also includes bugfixes and security fixes :

CVE-2008-4410: The vmi_write_ldt_entry function in
arch/x86/kernel/vmi_32.c in the Virtual Machine Interface (VMI) in the
Linux kernel 2.6.26.5 invokes write_idt_entry where write_ldt_entry
was intended, which allows local users to cause a denial of service
(persistent application failure) via crafted function calls, related
to the Java Runtime Environment (JRE) experiencing improper LDT
selector state.

sctp: Fix kernel panic while process protocol violation parameter.

CVE-2008-3528: The ext[234] filesystem code fails to properly handle
corrupted data structures. With a mounted filesystem image or
partition that have corrupted dir->i_size and dir->i_blocks, a user
performing either a read or write operation on the mounted image or
partition can lead to a possible denial of service by spamming the
logfile.

CVE-2008-3526: Integer overflow in the sctp_setsockopt_auth_key
function in net/sctp/socket.c in the Stream Control Transmission
Protocol (sctp) implementation in the Linux kernel allows remote
attackers to cause a denial of service (panic) or possibly have
unspecified other impact via a crafted sca_keylength field associated
with the SCTP_AUTH_KEY option.

CVE-2008-3525: Added missing capability checks in sbni_ioctl().

CVE-2008-4576: SCTP in Linux kernel before 2.6.25.18 allows remote
attackers to cause a denial of service (OOPS) via an INIT-ACK that
states the peer does not support AUTH, which causes the
sctp_process_init function to clean up active transports and triggers
the OOPS when the T1-Init timer expires.

CVE-2008-4445: The sctp_auth_ep_set_hmacs function in net/sctp/auth.c
in the Stream Control Transmission Protocol (sctp) implementation in
the Linux kernel before 2.6.26.4, when the SCTP-AUTH extension is
enabled, does not verify that the identifier index is within the
bounds established by SCTP_AUTH_HMAC_ID_MAX, which allows local users
to obtain sensitive information via a crafted SCTP_HMAC_IDENT IOCTL
request involving the sctp_getsockopt function.

CVE-2008-3792: net/sctp/socket.c in the Stream Control Transmission
Protocol (sctp) implementation in the Linux kernel 2.6.26.3 does not
verify that the SCTP-AUTH extension is enabled before proceeding with
SCTP-AUTH API functions, which allows attackers to cause a denial of
service (panic) via vectors that result in calls to (1)
sctp_setsockopt_auth_chunk, (2) sctp_setsockopt_hmac_ident, (3)
sctp_setsockopt_auth_key, (4) sctp_setsockopt_active_key, (5)
sctp_setsockopt_del_key, (6) sctp_getsockopt_maxburst, (7)
sctp_getsockopt_active_key, (8) sctp_getsockopt_peer_auth_chunks, or
(9) sctp_getsockopt_local_auth_chunks.

CVE-2008-4113: The sctp_getsockopt_hmac_ident function in
net/sctp/socket.c in the Stream Control Transmission Protocol (sctp)
implementation in the Linux kernel before 2.6.26.4, when the SCTP-AUTH
extension is enabled, relies on an untrusted length value to limit
copying of data from kernel memory, which allows local users to obtain
sensitive information via a crafted SCTP_HMAC_IDENT IOCTL request
involving the sctp_getsockopt function.

CVE-2008-3911: The proc_do_xprt function in net/sunrpc/sysctl.c in the
Linux kernel 2.6.26.3 does not check the length of a certain buffer
obtained from userspace, which allows local users to overflow a
stack-based buffer and have unspecified other impact via a crafted
read system call for the /proc/sys/sunrpc/transports file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=403346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=406656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=409961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=415372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=417821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=419134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=421321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=427244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=432488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=432490"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 189, 200, 264, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"kernel-debug-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-default-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-pae-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-rt-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-rt_debug-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-source-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-syms-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-vanilla-2.6.25.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-xen-2.6.25.18-0.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-default / kernel-pae / kernel-rt / etc");
}
