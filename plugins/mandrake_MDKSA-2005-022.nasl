#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:022. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(16259);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/01/14 15:20:32 $");

  script_cve_id("CVE-2004-0814", "CVE-2004-0816", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1016", "CVE-2004-1057", "CVE-2004-1058", "CVE-2004-1068", "CVE-2004-1069", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-1137", "CVE-2004-1151", "CVE-2004-1191", "CVE-2004-1235", "CVE-2005-0001", "CVE-2005-0003");
  script_xref(name:"MDKSA", value:"2005:022");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2005:022)");
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
"A number of vulnerabilities are fixed in the 2.4 and 2.6 kernels with
this advisory :

  - Multiple race conditions in the terminal layer of 2.4
    and 2.6 kernels (prior to 2.6.9) can allow a local
    attacker to obtain portions of kernel data or allow
    remote attackers to cause a kernel panic by switching
    from console to PPP line discipline, then quickly
    sending data that is received during the switch
    (CVE-2004-0814)

  - Richard Hart found an integer underflow problem in the
    iptables firewall logging rules that can allow a remote
    attacker to crash the machine by using a specially
    crafted IP packet. This is only possible, however, if
    firewalling is enabled. The problem only affects 2.6
    kernels and was fixed upstream in 2.6.8 (CVE-2004-0816)

  - Stefan Esser found several remote DoS confitions in the
    smbfs file system. This could be exploited by a hostile
    SMB server (or an attacker injecting packets into the
    network) to crash the client systems (CVE-2004-0883 and
    CVE-2004-0949)

  - Paul Starzetz and Georgi Guninski reported,
    independently, that bad argument handling and bad
    integer arithmetics in the IPv4 sendmsg handling of
    control messages could lead to a local attacker crashing
    the machine. The fixes were done by Herbert Xu
    (CVE-2004-1016)

  - Rob Landley discovered a race condition in the handling
    of /proc/.../cmdline where, under rare circumstances, a
    user could read the environment variables of another
    process that was still spawning leading to the potential
    disclosure of sensitive information such as passwords
    (CVE-2004-1058)

  - Paul Starzetz reported that the missing serialization in
    unix_dgram_recvmsg() which was added to kernel 2.4.28
    can be used by a local attacker to gain elevated (root)
    privileges (CVE-2004-1068)

  - Ross Kendall Axe discovered a possible kernel panic
    (DoS) while sending AF_UNIX network packets if certain
    SELinux-related kernel options were enabled. By default
    the CONFIG_SECURITY_NETWORK and CONFIG_SECURITY_SELINUX
    options are not enabled (CVE-2004-1069)

  - Paul Starzetz of isec.pl discovered several issues with
    the error handling of the ELF loader routines in the
    kernel. The fixes were provided by Chris Wright
    (CVE-2004-1070, CVE-2004-1071, CVE-2004-1072,
    CVE-2004-1073)

  - It was discovered that hand-crafted a.out binaries could
    be used to trigger a local DoS condition in both the 2.4
    and 2.6 kernels. The fixes were done by Chris Wright
    (CVE-2004-1074)

  - Paul Starzetz found bad handling in the IGMP code which
    could lead to a local attacker being able to crash the
    machine. The fix was done by Chris Wright
    (CVE-2004-1137)

  - Jeremy Fitzhardinge discovered two buffer overflows in
    the sys32_ni_syscall() and sys32_vm86_warning()
    functions that could be used to overwrite kernel memory
    with attacker-supplied code resulting in privilege
    escalation (CVE-2004-1151)

  - Paul Starzetz found locally exploitable flaws in the
    binary format loader's uselib() function that could be
    abused to allow a local user to obtain root privileges
    (CVE-2004-1235)

  - Paul Starzetz found an exploitable flaw in the page
    fault handler when running on SMP machines
    (CVE-2005-0001)

  - A vulnerability in insert_vm_struct could allow a locla
    user to trigger BUG() when the user created a large vma
    that overlapped with arg pages during exec
    (CVE-2005-0003)

  - Paul Starzetz also found a number of vulnerabilities in
    the kernel binfmt_elf loader that could lead a local
    user to obtain elevated (root) privileges
    (isec-0017-binfmt_elf)

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.

To update your kernel, please follow the directions located at :

http://www.mandrakesoft.com/security/kernelupdate

PLEASE NOTE: Mandrakelinux 10.0 users will need to upgrade to the
latest module-init-tools package prior to upgrading their kernel.
Likewise, MNF8.2 users will need to upgrade to the latest modutils
package prior to upgrading their kernel."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0017-binfmt_elf.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0022-pagefault.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ussg.iu.edu/hypermail/linux/kernel/0411.1/1222.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.22.41mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.25.13mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.28.0.rc1.5mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.3.25mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.8.1.24mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.22.41mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.25.13mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.28.0.rc1.5mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.3.25mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.8.1.24mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.4.28.0.rc1.5mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.8.1.24mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.4.22.41mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.4.25.13mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.3.25mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-64GB-2.6.8.1.24mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.4.22.41mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.4.25.13mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.6.3.25mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.22.41mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.6.3.25mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.6.8.1.24mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.22.41mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.25.13mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.28.0.rc1.5mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.3.25mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.8.1.24mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:module-init-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"kernel-2.4.25.13mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-2.6.3.25mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-enterprise-2.4.25.13mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-enterprise-2.6.3.25mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.4.25.13mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.3.25mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-p3-smp-64GB-2.4.25.13mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-p3-smp-64GB-2.6.3.25mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-secure-2.6.3.25mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-smp-2.4.25.13mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-smp-2.6.3.25mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-source-2.4.25-13mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-source-stripped-2.6.3-25mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"module-init-tools-3.0-1.2.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"kernel-2.4.28.0.rc1.5mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-2.6.8.1.24mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-enterprise-2.4.28.0.rc1.5mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-enterprise-2.6.8.1.24mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-i586-up-1GB-2.4.28.0.rc1.5mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.8.1.24mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-i686-up-64GB-2.6.8.1.24mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-secure-2.6.8.1.24mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-smp-2.4.28.0.rc1.5mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-smp-2.6.8.1.24mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-source-2.4-2.4.28-0.rc1.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-source-2.6-2.6.8.1-24mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-source-stripped-2.6-2.6.8.1-24mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"kernel-2.4.22.41mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-enterprise-2.4.22.41mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-i686-up-4GB-2.4.22.41mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-p3-smp-64GB-2.4.22.41mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kernel-secure-2.4.22.41mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kernel-smp-2.4.22.41mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kernel-source-2.4.22-41mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
