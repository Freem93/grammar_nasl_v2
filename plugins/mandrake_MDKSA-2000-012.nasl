#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:012. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61810);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:24 $");

  script_xref(name:"MDKSA", value:"2000:012");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2000:012)");
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
"POSIX 'Capabilities' have recently been implemented in the Linux
kernel. These 'Capabilities' are an additional form of privilege
control to enable more specific control over what privileged processes
can do. Capabilities are implemented as three (fairly large)
bitfields, which each bit representing a specific action a privileged
process can perform. By setting specific bits, the actions of
priviliged processes can be controlled -- access can be granted for
various functions only to the specific parts of a program that require
them. It is a security measure.

Important: If you use ReiserFS, please don't forget to do as following
after the upgrade :

  - If you used MandrakeUpdate or rpm -Uvh to upgrade,
    reinstall kernel 2.2.15 from native Mandrake 7.1

    - Type: cd /lib/modules/2.2.15-4mdk

    - Type: /sbin/depmod -a

    - Type: mkinitrd -f --ifneeded /boot/initrd-2.2.16-9mdk
      2.2.16-9mdk

    - You can now remove the older 2.2.15. Type: rpm -e
      kernel-2.2.15

    - Type: ln -sf /boot/initrd-2.2.16-9mdk /boot/initrd.img

    - Type: ln -sf /boot/System.map-2.2.16-9mdk
      /boot/System.map

    - Type: ln -sf /boot/vmlinuz-2.2.16-9mdk /boot/vmlinuz

    - In /etc/lilo.conf add: initrd=/boot/initrd-2.2.16-9mdk

    - Type: lilo -v"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-fb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-linus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:reiserfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-2.2.16_0.5.7-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-doc-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-fb-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-headers-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-linus-2.2.16-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-secure-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-smp-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-source-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-utils-2.2.16-9mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"reiserfs-utils-2.2.16_3.5.19-9mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
