#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61181);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-1898", "CVE-2011-2203", "CVE-2011-2494", "CVE-2011-3363", "CVE-2011-4110");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - Using PCI passthrough without interrupt remapping
    support allowed Xen hypervisor guests to generate MSI
    interrupts and thus potentially inject traps. A
    privileged guest user could use this flaw to crash the
    host or possibly escalate their privileges on the host.
    The fix for this issue can prevent PCI passthrough
    working and guests starting.(CVE-2011-1898, Important)

  - A flaw was found in the way CIFS (Common Internet File
    System) shares with DFS referrals at their root were
    handled. An attacker on the local network who is able to
    deploy a malicious CIFS server could create a CIFS
    network share that, when mounted, would cause the client
    system to crash. (CVE-2011-3363, Moderate)

  - A NULL pointer dereference flaw was found in the way the
    Linux kernel's key management facility handled
    user-defined key types. A local, unprivileged user could
    use the keyctl utility to cause a denial of service.
    (CVE-2011-4110, Moderate)

  - A flaw in the way memory containing security-related
    data was handled in tpm_read() could allow a local,
    unprivileged user to read the results of a previously
    run TPM command. (CVE-2011-1162, Low)

  - A NULL pointer dereference flaw was found in the Linux
    kernel's HFS file system implementation. A local
    attacker could use this flaw to cause a denial of
    service by mounting a disk that contains a specially
    crafted HFS file system with a corrupted MDB extent
    record. (CVE-2011-2203, Low)

  - The I/O statistics from the taskstats subsystem could be
    read without any restrictions. A local, unprivileged
    user could use this flaw to gather confidential
    information, such as the length of a password used in a
    process. (CVE-2011-2494, Low)

This update also fixes several bugs and adds one enhancement.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=3245
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f645be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-274.12.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
