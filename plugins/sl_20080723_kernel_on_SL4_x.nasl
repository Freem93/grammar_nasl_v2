#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60448);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-2136");

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
"These updated packages fix the following security issue :

  - a possible kernel memory leak was found in the Linux
    kernel Simple Internet Transition (SIT) INET6
    implementation. This could allow a local unprivileged
    user to cause a denial of service. (CVE-2008-2136,
    Important)

As well, these updated packages fix the following bugs :

  - a possible kernel hang on hugemem systems, due to a bug
    in NFS, which may have caused systems to become
    unresponsive, has been resolved.

  - an inappropriate exit condition occurred in the
    architecture-specific 'mmap()' realization, which fell
    into an infinite loop under certain conditions. On
    64-bit systems, this issue may have manifested itself to
    users as a soft lockup, or process hangs.

  - due to a bug in hardware initialization in the
    'ohci_hcd' kernel module, the kernel may have failed
    with a NULL pointer dereference. On 64-bit PowerPC
    systems, this may have caused booting to fail, and drop
    to xmon. On other platforms, a kernel oops occurred.

  - due to insufficient locks in task termination code, a
    panic may have occurred in the 'sys_times()' system call
    on SMP machines."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=2152
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e713a22"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/23");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-67.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-67.0.22.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
