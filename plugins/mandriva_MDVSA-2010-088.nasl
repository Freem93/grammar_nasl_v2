#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:088. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48181);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2009-3620", "CVE-2010-0410", "CVE-2010-0622", "CVE-2010-0623", "CVE-2010-1088");
  script_bugtraq_id(36824, 38058, 38165, 39044);
  script_xref(name:"MDVSA", value:"2010:088");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2010:088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

The ATI Rage 128 (aka r128) driver in the Linux kernel before
2.6.31-git11 does not properly verify Concurrent Command Engine (CCE)
state initialization, which allows local users to cause a denial of
service (NULL pointer dereference and system crash) or possibly gain
privileges via unspecified ioctl calls. (CVE-2009-3620)

fs/namei.c in Linux kernel 2.6.18 through 2.6.34 does not always
follow NFS automount symlinks, which allows attackers to have an
unknown impact, related to LOOKUP_FOLLOW. (CVE-2010-1088)

The wake_futex_pi function in kernel/futex.c in the Linux kernel
before 2.6.33-rc7 does not properly handle certain unlock operations
for a Priority Inheritance (PI) futex, which allows local users to
cause a denial of service (OOPS) and possibly have unspecified other
impact via vectors involving modification of the futex value from user
space. (CVE-2010-0622)

drivers/connector/connector.c in the Linux kernel before 2.6.32.8
allows local users to cause a denial of service (memory consumption
and system crash) by sending the kernel many NETLINK_CONNECTOR
messages. (CVE-2010-0410)

The futex_lock_pi function in kernel/futex.c in the Linux kernel
before 2.6.33-rc7 does not properly manage a certain reference count,
which allows local users to cause a denial of service (OOPS) via
vectors involving an unmount of an ext3 filesystem. (CVE-2010-0623)

Aditionally, the kernel was updated to the 2.6.31.13 stable release,
it was added support for Cirrus Logic CS420x HDA codec, Wacom driver
was updated to version 0.8.5-12 and there is a fix in the driver for
backlight on Eee PC 1201HA.

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.31.13-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.31.13-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.31.13-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.31.13-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-2.6.31.13-desktop-1mnb-5.10.91.9-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"broadcom-wl-kernel-2.6.31.13-desktop586-1mnb-5.10.91.9-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-2.6.31.13-server-1mnb-5.10.91.9-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-desktop-latest-5.10.91.9-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"broadcom-wl-kernel-desktop586-latest-5.10.91.9-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-server-latest-5.10.91.9-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-2.6.31.13-desktop-1mnb-0.17.4-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"em8300-kernel-2.6.31.13-desktop586-1mnb-0.17.4-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-2.6.31.13-server-1mnb-0.17.4-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-desktop-latest-0.17.4-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"em8300-kernel-desktop586-latest-0.17.4-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-server-latest-0.17.4-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-2.6.31.13-desktop-1mnb-8.650-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"fglrx-kernel-2.6.31.13-desktop586-1mnb-8.650-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-2.6.31.13-server-1mnb-8.650-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-desktop-latest-8.650-1.20100428.1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"fglrx-kernel-desktop586-latest-8.650-1.20100428.1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-server-latest-8.650-1.20100428.1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.31.13-desktop-1mnb-1.19-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.31.13-desktop586-1mnb-1.19-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.31.13-server-1mnb-1.19-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-desktop-latest-1.19-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-desktop586-latest-1.19-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-server-latest-1.19-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-2.6.31.13-desktop-1mnb-7.80.02.05-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hsfmodem-kernel-2.6.31.13-desktop586-1mnb-7.80.02.05-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-2.6.31.13-server-1mnb-7.80.02.05-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-desktop-latest-7.80.02.05-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hsfmodem-kernel-desktop586-latest-7.80.02.05-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-server-latest-7.80.02.05-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-devel-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-devel-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-devel-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-doc-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-devel-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-devel-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-source-2.6.31.13-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-source-latest-2.6.31.13-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-2.6.31.13-desktop-1mnb-1.4.11-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libafs-kernel-2.6.31.13-desktop586-1mnb-1.4.11-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-2.6.31.13-server-1mnb-1.4.11-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-desktop-latest-1.4.11-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libafs-kernel-desktop586-latest-1.4.11-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-server-latest-1.4.11-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-2.6.31.13-desktop-1mnb-0.8.6-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lirc-kernel-2.6.31.13-desktop586-1mnb-0.8.6-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-2.6.31.13-server-1mnb-0.8.6-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-desktop-latest-0.8.6-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lirc-kernel-desktop586-latest-0.8.6-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-server-latest-0.8.6-1.20100428.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-2.6.31.13-desktop-1mnb-4.43-28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lzma-kernel-2.6.31.13-desktop586-1mnb-4.43-28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-2.6.31.13-server-1mnb-4.43-28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-desktop-latest-4.43-1.20100428.28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lzma-kernel-desktop586-latest-4.43-1.20100428.28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-server-latest-4.43-1.20100428.28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-2.6.31.13-desktop-1mnb-0.9.4-4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"madwifi-kernel-2.6.31.13-desktop586-1mnb-0.9.4-4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-2.6.31.13-server-1mnb-0.9.4-4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-desktop-latest-0.9.4-1.20100428.4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20100428.4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-server-latest-0.9.4-1.20100428.4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-2.6.31.13-desktop-1mnb-185.18.36-4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia-current-kernel-2.6.31.13-desktop586-1mnb-185.18.36-4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-2.6.31.13-server-1mnb-185.18.36-4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-desktop-latest-185.18.36-1.20100428.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia-current-kernel-desktop586-latest-185.18.36-1.20100428.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-server-latest-185.18.36-1.20100428.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-2.6.31.13-desktop-1mnb-173.14.20-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia173-kernel-2.6.31.13-desktop586-1mnb-173.14.20-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-2.6.31.13-server-1mnb-173.14.20-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-desktop-latest-173.14.20-1.20100428.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia173-kernel-desktop586-latest-173.14.20-1.20100428.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-server-latest-173.14.20-1.20100428.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-2.6.31.13-desktop-1mnb-96.43.13-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia96xx-kernel-2.6.31.13-desktop586-1mnb-96.43.13-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-2.6.31.13-server-1mnb-96.43.13-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-desktop-latest-96.43.13-1.20100428.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia96xx-kernel-desktop586-latest-96.43.13-1.20100428.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-server-latest-96.43.13-1.20100428.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-2.6.31.13-desktop-1mnb-2.9.11-0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-2.6.31.13-desktop586-1mnb-2.9.11-0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-2.6.31.13-server-1mnb-2.9.11-0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-desktop-latest-2.9.11-1.20100428.0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20100428.0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-server-latest-2.9.11-1.20100428.0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-2.6.31.13-desktop-1mnb-3.3-11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"squashfs-lzma-kernel-2.6.31.13-desktop586-1mnb-3.3-11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-2.6.31.13-server-1mnb-3.3-11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20100428.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20100428.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-server-latest-3.3-1.20100428.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-2.6.31.13-desktop-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-2.6.31.13-desktop586-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-2.6.31.13-server-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-desktop-latest-3.0.8-1.20100428.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-3.0.8-1.20100428.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-server-latest-3.0.8-1.20100428.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-2.6.31.13-desktop-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-2.6.31.13-desktop586-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-2.6.31.13-server-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-desktop-latest-3.0.8-1.20100428.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-3.0.8-1.20100428.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-server-latest-3.0.8-1.20100428.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-2.6.31.13-desktop-1mnb-4.8.02.0030-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-2.6.31.13-desktop586-1mnb-4.8.02.0030-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-2.6.31.13-server-1mnb-4.8.02.0030-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-desktop-latest-4.8.02.0030-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-desktop586-latest-4.8.02.0030-1.20100428.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-server-latest-4.8.02.0030-1.20100428.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
