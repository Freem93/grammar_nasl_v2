#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66551);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/23 10:55:16 $");

  script_cve_id("CVE-2013-0153");

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
"This update fixes the following security issue :

  - A flaw was found in the way the Xen hypervisor AMD IOMMU
    driver handled interrupt remapping entries. By default,
    a single interrupt remapping table is used, and old
    interrupt remapping entries are not cleared, potentially
    allowing a privileged guest user in a guest that has a
    passed- through, bus-mastering capable PCI device to
    inject interrupt entries into others guests, including
    the privileged management domain (Dom0), leading to a
    denial of service. (CVE-2013-0153, Moderate)

This update also fixes the following bugs :

  - When a process is opening a file over NFSv4, sometimes
    an OPEN call can succeed while the following GETATTR
    operation fails with an NFS4ERR_DELAY error. The NFSv4
    code did not handle such a situation correctly and
    allowed an NFSv4 client to attempt to use the buffer
    that should contain the GETATTR information. However,
    the buffer did not contain the valid GETATTR
    information, which caused the client to return a
    '-ENOTDIR' error. Consequently, the process failed to
    open the requested file. This update backports a patch
    that adds a test condition verifying validity of the
    GETATTR information. If the GETATTR information is
    invalid, it is obtained later and the process opens the
    requested file as expected.

  - Previously, the xdr routines in NFS version 2 and 3
    conditionally updated the res->count variable. Read
    retry attempts after a short NFS read() call could fail
    to update the res->count variable, resulting in
    truncated read data being returned. With this update,
    the res->count variable is updated unconditionally so
    this bug can no longer occur.

  - When handling requests from Intelligent Platform
    Management Interface (IPMI) clients, the IPMI driver
    previously used two different locks for an IPMI request.
    If two IPMI clients sent their requests at the same
    time, each request could receive one of the locks and
    then wait for the second lock to become available. This
    resulted in a deadlock situation and the system became
    unresponsive. The problem could occur more likely in
    environments with many IPMI clients. This update
    modifies the IPMI driver to handle the received messages
    using tasklets so the driver now uses a safe locking
    technique when handling IPMI requests and the mentioned
    deadlock can no longer occur.

  - Incorrect locking around the cl_state_owners list could
    cause the NFSv4 state reclaimer thread to enter an
    infinite loop while holding the Big Kernel Lock (BLK).
    As a consequence, the NFSv4 client became unresponsive.
    With this update, safe list iteration is used, which
    prevents the NFSv4 client from hanging in this scenario.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1305&L=scientific-linux-errata&T=0&P=1682
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a407af67"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-348.6.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
