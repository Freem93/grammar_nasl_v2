#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60372);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2007-5904");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"These updated kernel packages fix the following security issue :

A buffer overflow flaw was found in the CIFS virtual file system. A
remote authenticated user could issue a request that could lead to a
denial of service. (CVE-2007-5904, Moderate)

As well, these updated packages fix the following bugs :

  - a bug was found in the Linux kernel audit subsystem.
    When the audit daemon was setup to log the execve system
    call with a large number of arguments, the kernel could
    run out out memory while attempting to create audit log
    messages. This could cause a kernel panic. In these
    updated packages, large audit messages are split into
    acceptable sizes, which resolves this issue.

  - on certain Intel chipsets, it was not possible to load
    the acpiphp module using the 'modprobe acpiphp' command.
    Because the acpiphp module did not recurse across PCI
    bridges, hardware detection for PCI hot plug slots
    failed. In these updated packages, hardware detection
    works correctly.

  - on IBM System z architectures that run the IBM z/VM
    hypervisor, the IBM eServer zSeries HiperSockets network
    interface (layer 3) allowed ARP packets to be sent and
    received, even when the 'NOARP' flag was set. These ARP
    packets caused problems for virtual machines.

  - it was possible for the iounmap function to sleep while
    holding a lock. This may have caused a deadlock for
    drivers and other code that uses the iounmap function.
    In these updated packages, the lock is dropped before
    the sleep code is called, which resolves this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0803&L=scientific-linux-errata&T=0&P=754
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2cea653"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-67.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-67.0.7.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
