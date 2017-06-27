#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(81308);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/19 15:11:12 $");

  script_cve_id("CVE-2014-7822");

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
"  - A flaw was found in the way the Linux kernel's splice()
    system call validated its parameters. On certain file
    systems, a local, unprivileged user could use this flaw
    to write past the maximum file size, and thus crash the
    system. (CVE-2014-7822, Moderate)

This update also fixes the following bugs :

  - Previously, hot-unplugging of a virtio-blk device could
    in some cases lead to a kernel panic, for example during
    in-flight I/O requests. This update fixes race condition
    in the hot-unplug code in the virtio_blk.ko module. As a
    result, hot unplugging of the virtio-blk device no
    longer causes the guest kernel oops when there are
    in-flight I/O requests.

  - Before this update, due to a bug in the error-handling
    path, a corrupted metadata block could be used as a
    valid block. With this update, the error handling path
    has been fixed and more checks have been added to verify
    the metadata block. Now, when a corrupted metadata block
    is encountered, it is properly marked as corrupted and
    handled accordingly.

  - Previously, an incorrectly initialized variable resulted
    in a random value being stored in the variable that
    holds the number of default ACLs, and is sent in the
    SET_PATH_INFO data structure. Consequently, the setfacl
    command could, under certain circumstances, fail with an
    'Invalid argument' error. With this update, the variable
    is correctly initialized to zero, thus fixing the bug.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1502&L=scientific-linux-errata&T=0&P=901
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0af3076"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-402.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-402.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
