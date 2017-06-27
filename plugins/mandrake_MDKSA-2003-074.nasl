#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:074. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14057);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0001", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0462", "CVE-2003-0476");
  script_xref(name:"MDKSA", value:"2003:074");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2003:074)");
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
"Multiple vulnerabilities were discovered and fixed in the Linux
kernel.

  - CVE-2003-0001: Multiple ethernet network card drivers do
    not pad frames with null bytes which allows remote
    attackers to obtain information from previous packets or
    kernel memory by using special malformed packets.

  - CVE-2003-0244: The route cache implementation in the 2.4
    kernel and the Netfilter IP conntrack module allows
    remote attackers to cause a Denial of Service (DoS) via
    CPU consumption due to packets with forged source
    addresses that cause a large number of hash table
    collisions related to the PREROUTING chain.

  - CVE-2003-0246: The ioperm implementation in 2.4.20 and
    earlier kernels does not properly restrict privileges,
    which allows local users to gain read or write access to
    certain I/O ports.

  - CVE-2003-0247: A vulnerability in the TTY layer of the
    2.4 kernel allows attackers to cause a kernel oops
    resulting in a DoS.

  - CVE-2003-0248: The mxcsr code in the 2.4 kernel allows
    attackers to modify CPU state registers via a malformed
    address.

  - CVE-2003-0462: A file read race existed in the execve()
    system call.

Kernels for 9.1/x86 are also available (see MDKSA-2003:066).

MandrakeSoft encourages all users to upgrade to these new kernels.

For full instructions on how to properly upgrade your kernel, please
review http://www.mandrakesecure.net/en/docs/magic.php."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=105664924024009&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=105664924024009&w=2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.19.35mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.4.19.35mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.19.35mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.19.35mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.19.35mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/15");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-BOOT-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-doc-2.4.19-35mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-enterprise-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-secure-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-smp-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"kernel-source-2.4.19-35mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-BOOT-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-doc-2.4.19-35mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-enterprise-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-secure-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-smp-2.4.19.35mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-source-2.4.19-35mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
