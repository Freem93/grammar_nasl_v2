#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:039. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14023);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/07/15 14:49:03 $");

  script_cve_id("CVE-2002-1380", "CVE-2003-0001", "CVE-2003-0127");
  script_xref(name:"MDKSA", value:"2003:039");

  script_name(english:"Mandrake Linux Security Advisory : kernel22 (MDKSA-2003:039)");
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
"A number of vulnerabilities have been found in the Linux 2.2 kernel
that have been addressed with the latest 2.2.25 release.

A bug in the kernel module loader code could allow a local user to
gain root privileges. This is done by a local user using ptrace and
attaching to a modprobe process that is spawned if the user triggers
the loading of a kernel module.

A temporary workaround can be used to defend against this flaw. It is
possible to temporarily disable the kmod kernel module loading
subsystem in the kernel after all of the required kernel modules have
been loaded. Be sure that you do not need to load additional kernel
modules after implementing this workaround. To use it, as root 
execute :

echo /no/such/file >/proc/sys/kernel/modprobe

To automate this, you may wish to add it as the last line of the
/etc/rc.d/rc.local file. You can revert this change by replacing the
content '/sbin/modprobe' in the /proc/sys/kernel/modprobe file. The
root user can still manually load kernel modules with this workaround
in place.

As well, multiple ethernet device drivers do not pad frames with null
bytes, which could allow remote attackers to obtain information from
previous packets or kernel memory by using malformed packets.

Finally, the 2.2 kernel allows local users to cause a crash of the
host system by using the mmap() function with a PROT_READ parameter to
access non-readable memory pages through the /proc/pid/mem interface.

All users are encouraged to upgrade to the latest kernel version
provided.

For instructions on how to upgrade your kernel in Mandrake Linux,
please refer to :

http://www.mandrakesecure.net/en/kernelupdate.php"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel22-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:reiserfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-2.2.25_0.5.11-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"alsa-source-2.2.25_0.5.11-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-doc-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-headers-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-pcmcia-cs-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-secure-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-smp-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-source-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"kernel-utils-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"reiserfs-utils-2.2.25_3.5.29-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-smp-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"kernel22-source-2.2.25-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel22-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel22-smp-2.2.25-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel22-source-2.2.25-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
