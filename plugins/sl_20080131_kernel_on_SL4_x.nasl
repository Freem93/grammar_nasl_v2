#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60354);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-4130", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0001");

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
"These updated kernel packages fix the following security issues :

A flaw was found in the virtual filesystem (VFS). A local unprivileged
user could truncate directories to which they had write permission;
this could render the contents of the directory inaccessible.
(CVE-2008-0001, Important)

A flaw was found in the implementation of ptrace. A local unprivileged
user could trigger this flaw and possibly cause a denial of service
(system hang). (CVE-2007-5500, Important)

A flaw was found in the way the Red Hat Enterprise Linux 4 kernel
handled page faults when a CPU used the NUMA method for accessing
memory on Itanium architectures. A local unprivileged user could
trigger this flaw and cause a denial of service (system panic).
(CVE-2007-4130, Important)

A possible NULL pointer dereference was found in the chrp_show_cpuinfo
function when using the PowerPC architecture. This may have allowed a
local unprivileged user to cause a denial of service (crash).
(CVE-2007-6694, Moderate)

A flaw was found in the way core dump files were created. If a local
user can get a root-owned process to dump a core file into a
directory, which the user has write access to, they could gain read
access to that core file. This could potentially grant unauthorized
access to sensitive information. (CVE-2007-6206, Moderate)

Two buffer overflow flaws were found in the Linux kernel ISDN
subsystem. A local unprivileged user could use these flaws to cause a
denial of service. (CVE-2007-6063, CVE-2007-6151, Moderate)

As well, these updated packages fix the following bug :

  - when moving volumes that contain multiple segments, and
    a mirror segment is not the first in the mapping table,
    running the 'pvmove /dev/[device] /dev/[device]' command
    caused a kernel panic. A 'kernel: Unable to handle
    kernel paging request at virtual address [address]'
    error was logged by syslog."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0802&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f4768b8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-67.0.4.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
