#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(84078);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/11/14 14:25:31 $");

  script_cve_id("CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9585", "CVE-2015-1805", "CVE-2015-3331");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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
"* It was found that the Linux kernel's implementation of vectored pipe
read and write functionality did not take into account the I/O vectors
that were already processed when retrying after a failed atomic access
operation, potentially resulting in memory corruption due to an I/O
vector array overrun. A local, unprivileged user could use this flaw
to crash the system or, potentially, escalate their privileges on the
system. (CVE-2015-1805, Important)

* A buffer overflow flaw was found in the way the Linux kernel's Intel
AES-NI instructions optimized version of the RFC4106 GCM mode
decryption functionality handled fragmented packets. A remote attacker
could use this flaw to crash, or potentially escalate their privileges
on, a system over a connection with an active AES-GCM mode IPSec
security association. (CVE-2015-3331, Important)

* An information leak flaw was found in the way the Linux kernel
changed certain segment registers and thread-local storage (TLS)
during a context switch. A local, unprivileged user could use this
flaw to leak the user space TLS base address of an arbitrary process.
(CVE-2014-9419, Low)

* It was found that the Linux kernel's ISO file system implementation
did not correctly limit the traversal of Rock Ridge extension
Continuation Entries (CE). An attacker with physical access to the
system could use this flaw to trigger an infinite loop in the kernel,
resulting in a denial of service. (CVE-2014-9420, Low)

* An information leak flaw was found in the way the Linux kernel's
Virtual Dynamic Shared Object (vDSO) implementation performed address
randomization. A local, unprivileged user could use this flaw to leak
kernel memory addresses to user-space. (CVE-2014-9585, Low)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=5447
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0cfacc3a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-504.23.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-504.23.4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
