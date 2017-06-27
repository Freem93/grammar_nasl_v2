#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60939);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-4526");

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

  - A flaw was found in the sctp_icmp_proto_unreachable()
    function in the Linux kernel's Stream Control
    Transmission Protocol (SCTP) implementation. A remote
    attacker could use this flaw to cause a denial of
    service. (CVE-2010-4526, Important)

This update also fixes the following bugs :

  - Due to an off-by-one error, gfs2_grow failed to take the
    very last 'rgrp' parameter into account when adding up
    the new free space. With this update, the GFS2 kernel
    properly counts all the new resource groups and fixes
    the 'statfs' file correctly. (BZ#666792)

  - Prior to this update, a multi-threaded application,
    which invoked popen(3) internally, could cause a thread
    stall by FILE lock corruption. The application program
    waited for a FILE lock in glibc, but the lock seemed to
    be corrupted, which was caused by a race condition in
    the COW (Copy On Write) logic. With this update, the
    race condition was corrected and FILE lock corruption no
    longer occurs. (BZ#667050)

  - If an error occurred during I/O, the SCSI driver reset
    the 'megaraid_sas' controller to restore it to normal
    state. However, on Scientific Linux 5, the waiting time
    to allow a full reset completion for the 'megaraid_sas'
    controller was too short. The driver incorrectly
    recognized the controller as stalled, and, as a result,
    the system stalled as well. With this update, more time
    is given to the controller to properly restart, thus,
    the controller operates as expected after being reset.
    (BZ#667141)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=866
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f2d17bf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=666792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=667050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=667141"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-238.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-238.1.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
