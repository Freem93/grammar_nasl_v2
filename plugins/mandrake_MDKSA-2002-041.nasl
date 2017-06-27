#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:041. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13945);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-0060");
  script_xref(name:"MDKSA", value:"2002:041");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2002:041)");
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
"A problem was discovered in the CIPE (VPN tunnel) implementation in
the Linux kernel where a malformed packet could cause a crash.

Andrew Griffiths discovered a vulnerability that allows remote
machines to read random memory by utilizing a bug in the ICMP
implementation of Linux kernels. This only affects kernels prior to
2.4.0-test6 and 2.2.18; all Mandrake Linux 2.4 kernels are not
vulnerable to this problem.

Another problem was discovered by the Linux Netfilter team in the IRC
connection tracking component of netfilter in Linux 2.4 kernels. It
consists of a very broad netmask setting which is applied to check if
an IRC DCC connection through a masqueraded firewall should be
allowed. This would lead to unwanted ports being opened on the
firewall which could possibly allow inbound connections depending on
the firewall rules in use.

The 2.2 and 2.4 kernels are also affected by the zlib double-free()
problem as routines from the compression library are used by functions
that uncompress filesystems loaded into ramdisks and other occassions
that are not security-critical. The kernel also uses the compression
library in the PPP layer as well as the freeswan IPSec kernel module.

As well, a number of other non-security fixes are present in these
kernels, including new and enhanced drivers, LSB compliance, and more.

MandrakeSoft encourages all users to upgrade their kernel as soon as
possible to these new 2.2 and 2.4 kernels.

NOTE: This update cannot be accomplished via MandrakeUpdate; it must
be done on the console. This prevents one from upgrading a kernel
instead of installing a new kernel. To upgrade, please ensure that you
have first upgraded iptables, mkinitrd, and initscripts packages if
they are applicable to your platform. Use 'rpm -ivh kernel_package' to
install the new kernel. Prior to rebooting, double-check your
/etc/lilo.conf, /boot/grub/menu.lst, or /etc/yaboot.conf (PPC users
only) to ensure that you are able to boot properly into both old and
new kernels (this will allow you to boot into the old kernel if the
new kernel does not work to your liking).

LILO users should execute '/sbin/lilo -v', GRUB users should execute
'sh /boot/grun/install.sh', and PPC users must type '/sbin/ybin -v' to
write the boot record in order to reboot into the new kernel if you
made any changes to the respective boot configuration files.

New kernels for Mandrake Linux 8.1/IA64 will be available shortly."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:devfsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:initscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables-ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.18.8.1mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.18.8.2mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.18.8.2mdk-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.4.18.8.1mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.4.18.8.2mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.18.8.1mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.18.8.2mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.18.8.1mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.18.8.2mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.18.8.1mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.18.8.2mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mkinitrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:reiserfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-doc-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-headers-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-secure-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-smp-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-source-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-utils-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-6.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-doc-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-headers-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-secure-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-smp-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-source-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-utils-2.2.19-6.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-6.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"initscripts-5.83-7.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"iptables-1.2.5-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"iptables-ipv6-1.2.5-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-2.4.18.8.2mdk-pcmcia-cs-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-BOOT-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-doc-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-doc-html-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-doc-pdf-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-doc-ps-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-enterprise-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-secure-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-smp-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-source-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-2.2.20-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-smp-2.2.20-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-source-2.2.20-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mkinitrd-3.1.6-28.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"iptables-1.2.5-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"iptables-ipv6-1.2.5-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-2.4.18.8.2mdk-pcmcia-cs-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-doc-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-doc-html-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-doc-pdf-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-doc-ps-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-enterprise-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-secure-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-smp-2.4.18.8.2mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-source-2.4.18-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-2.2.20-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-smp-2.2.20-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-source-2.2.20-9.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mkinitrd-3.1.6-28.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"devfsd-1.3.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-2.4.18.8.1mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-BOOT-2.4.18.8.1mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-doc-2.4.18-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-doc-html-2.4.18-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-doc-pdf-2.4.18-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-doc-ps-2.4.18-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-enterprise-2.4.18.8.1mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-secure-2.4.18.8.1mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-smp-2.4.18.8.1mdk-1-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-source-2.4.18-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel22-2.2.20-9.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel22-smp-2.2.20-9.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel22-source-2.2.20-9.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
