#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:082. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13895);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:43:25 $");

  script_cve_id("CVE-2001-0851", "CVE-2001-0907", "CVE-2001-1384");
  script_xref(name:"MDKSA", value:"2001:082-1");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2001:082-1)");
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
"Rafal Wojtczuk found a vulnerability in the 2.2.19 and 2.4.11 Linux
kernels with the ptrace code and deeply nested symlinks spending an
arbitrary amount of time in the kernel code. The ptrace vulnerability
could be used by local users to gain root privilege, the symlink
vulnerability could result in a local DoS.

Update :

There is an additional vulnerability in the kernel's syncookie code
which could potentially allow a remote attacker to guess the cookie
and bypass existing firewall rules. The discovery was found by Manfred
Spraul and Andi Kleen.

NOTE: This update is *not* meant to be done via MandrakeUpdate! You
must download the necessary RPMs and upgrade manually by following
these steps :

1. Type: rpm -ivh kernel-[version].i586.rpm 2. Type: mv
kernel-[version].i586.rpm /tmp 3. Type: rpm -Fvh *.rpm 4a. You may
wish to edit /etc/lilo.conf to ensure a new entry is in place. The new
kernel will be the last entry. Change any options you need to change.
You will also want to create a new entry with the initrd and image
directives pointing to the old kernel's vmlinuz and initrd images so
you may also boot from the old images if required. 4b. PPC users must
execute some additional instructions. First edit /etc/yaboot.conf and
add a new entry for the kernel and change any options that you need to
change. You must also create a new initrd image to enable USB support
for keyboards and mice by typing: mkinitrd --with=usb-ohci
/boot/initrd-2.2.19-19.1mdk 2.2.19-19.1mdk 5a. Type: /sbin/lilo -v 5b.
PPC users must type: /sbin/ybin -v

You may then reboot and use the new kernel and remove the older kernel
when you are comfortable using the upgraded one."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/cgi-bin/archive.pl?id=1&mid=221337"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-linus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-linus2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-secure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:reiserfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/11/20");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-doc-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-headers-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-linus-2.2.20-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-secure-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-smp-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-source-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-utils-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-6.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-doc-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-headers-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-linus-2.2.20-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-secure-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-smp-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-source-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-utils-2.2.19-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-6.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-linus2.2-2.2.20-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-2.2.19-20.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-secure-2.2.19-20.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-smp-2.2.19-20.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel22-source-2.2.19-20.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel-linus2.2-2.2.20-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-2.2.19-20.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-secure-2.2.19-20.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-smp-2.2.19-20.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-source-2.2.19-20.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
