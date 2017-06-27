#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:037. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61910);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:25 $");

  script_cve_id("CVE-2001-0316", "CVE-2001-1390", "CVE-2001-1391", "CVE-2001-1392", "CVE-2001-1393", "CVE-2001-1394", "CVE-2001-1395", "CVE-2001-1396", "CVE-2001-1397", "CVE-2001-1398", "CVE-2001-1399", "CVE-2001-1400");
  script_xref(name:"MDKSA", value:"2001:037");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2001:037)");
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
"A number of security problems have been found in the Linux kernels
prior to the latest 2.2.19 kernel. Following is a list of problems
based on the 2.2.19 release notes as found on http://www.linux.org.uk/

  - binfmt_misc used user pages directly

    - the CPIA driver had an off-by-one error in the buffer
      code which made it possible for users to write into
      kernel memory

  - the CPUID and MSR drivers had a problem in the module
    unloading code which could cause a system a crash if
    they were set to automatically load and unload

  - there was a possible hang in the classifier code

    - the getsockopt and setsockopt system calls did not
      handle sign bits correctly which made a local DoS and
      other attacks possible

  - the sysctl system call did not handle sign bits
    correctly which allowed a user to write in kernel memory

  - ptrace/exec races that could give a local user extra
    privileges

    - possible abuse of a boundary case in the sockfilter
      code

    - SYSV shared memory code could overwrite recently freed
      memory which might cause problems

  - the packet lengh checks in the masquerading code were a
    bit lax (probably not exploitable)

  - some x86 assembly bugs caused the wrong number of bytes
    to be copied

    - a local user could deadlock the kernel due to bugs in
      the UDP port allocation.

All of these problems are corrected in the 2.2.19 kernel and it is
highly recommended that all Linux-Mandrake users upgrade their systems
to this kernel.

It is also recommended that you download the necessary RPMs and
upgrade manually by following these steps :

  - type: rpm -ivh kernel-2.2.19-4.1mdk.i586.rpm

    - type: mv kernel-2.2.19-4.1mdk.i586.rpm /tmp

    - type: rpm -Fvh *.rpm

    - type: mkinitrd -f --ifneeded
      /boot/initrd-2.2.19-4.1mdk 2.2.19-4.1mdk

    - type: ln -sf /boot/initrd-2.2.19-4.1mdk
      /boot/initrd.img

    - edit /etc/lilo.conf and double-check the options

    - type: /sbin/lilo -v

Replace the kernel revision noted in the above instructions with those
from the packages you downloaded. You will then be able to reboot and
use the new kernel and remove the older kernel when you are
comfortable using the upgraded one."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-linus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:reiserfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/04/17");
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
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-doc-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-headers-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-secure-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-smp-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-source-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"kernel-utils-2.2.19-4.6mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-4.6mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-doc-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-headers-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-secure-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-smp-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-source-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"kernel-utils-2.2.19-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-4.5mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-doc-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-headers-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-linus-2.2.19-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-secure-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-smp-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-source-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"kernel-utils-2.2.19-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-4.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-doc-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-headers-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-linus-2.2.19-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-secure-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-smp-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-source-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"kernel-utils-2.2.19-4.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-4.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-2.2.19_0.5.10b-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-source-2.2.19_0.5.10b-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-doc-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-headers-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-linus-2.2.19-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-secure-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-smp-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-source-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-utils-2.2.19-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"reiserfs-utils-2.2.19_3.5.29-4.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
