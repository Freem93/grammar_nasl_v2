#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:086. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21575);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2006-0744", "CVE-2006-1052", "CVE-2006-1242", "CVE-2006-1522", "CVE-2006-1525", "CVE-2006-1527", "CVE-2006-2071", "CVE-2006-2271", "CVE-2006-2272");
  script_xref(name:"MDKSA", value:"2006:086");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2006:086)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel :

Prior to Linux kernel 2.6.16.5, the kernel does not properly handle
uncanonical return addresses on Intel EM64T CPUs which causes the
kernel exception handler to run on the user stack with the wrong GS
(CVE-2006-0744).

The selinux_ptrace logic hooks in SELinux for 2.6.6 allow local users
with ptrace permissions to change the tracer SID to an SID of another
process (CVE-2006-1052).

Prior to 2.6.16, the ip_push_pending_frames function increments the IP
ID field when sending a RST after receiving unsolicited TCP SYN-ACK
packets, which allows a remote attacker to conduct an idle scan
attack, bypassing any intended protection against such an attack
(CVE-2006-1242).

In kernel 2.6.16.1 and some earlier versions, the sys_add_key function
in the keyring code allows local users to cause a DoS (OOPS) via
keyctl requests that add a key to a user key instead of a keyring key,
causing an invalid dereference (CVE-2006-1522).

Prior to 2.6.16.8, the ip_route_input function allows local users to
cause a DoS (panic) via a request for a route for a multicast IP
address, which triggers a null dereference (CVE-2006-1525).

Prior to 2.6.16.13, the SCTP-netfilter code allows remote attackers to
cause a DoS (infinite loop) via unknown vectors that cause an invalid
SCTP chunk size to be processed (CVE-2006-1527).

Prior to 2.6.16, local users can bypass IPC permissions and modify a
read-only attachment of shared memory by using mprotect to give write
permission to the attachment (CVE-2006-2071).

Prior to 2.6.17, the ECNE chunk handling in SCTP (lksctp) allows
remote attackers to cause a DoS (kernel panic) via an unexpected
chucnk when the session is in CLOSED state (CVE-2006-2271).

Prior to 2.6.17, SCTP (lksctp) allows remote attacker to cause a DoS
(kernel panic) via incoming IP fragmented COOKIE_ECHO and HEARTBEAT
SCTP control chunks (CVE-2006-2272).

In addition to these security fixes, other fixes have been included
such as :

  - fix a scheduler deadlock

    - Yenta oops fix

    - ftdi_sio: adds support for iPlus devices

    - enable kprobes on i386 and x86_64

    - avoid a panic on bind mount of autofs owned directory

    - fix a kernel OOPs when booting with 'console=ttyUSB0'
      but without a USB-serial dongle plugged in

  - make dm-mirror not issue invalid resync requests

    - fix media change detection on scsi removable devices

    - add support for the realtek 8168 chipset

    - update hfsplus driver to 2.6.16 state

    - backport 'Gilgal' support from e1000 7.0.33

    - selected ACPI video fixes

    - update 3w-9xxx to 2.26.02.005 (9550SX support)

    - fix a deadlock in the ext2 filesystem

    - fix usbserial use-after-free bug

    - add i945GM DRI support

    - S3 resume fixes

    - add ECS PF22 hda model support

    - SMP suspend

    - CPU hotplug

    - miscellaneous AGP fixes

    - added sata-suspend patch for 2.6.12 for Napa platform

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.

As well, updated mkinitrd and bootsplash packages are provided to fix
minor issues; users should upgrade both packages prior to installing a
new kernel.

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bootsplash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xbox-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.12.21mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mkinitrd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2006.0", reference:"bootsplash-3.1.12-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-BOOT-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-smp-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-2.6-2.6.12-21mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-stripped-2.6-2.6.12-21mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xbox-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xen0-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xenU-2.6.12.21mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mkinitrd-4.2.17-17.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
