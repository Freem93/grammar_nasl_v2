#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(94432);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/16 16:05:34 $");

  script_cve_id("CVE-2016-1583", "CVE-2016-5195");
  script_xref(name:"IAVA", value:"2016-A-0306");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64 (Dirty COW)");
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
"Security Fix(es) :

  - A race condition was found in the way the Linux kernel's
    memory subsystem handled the copy-on-write (COW)
    breakage of private read-only memory mappings. An
    unprivileged, local user could use this flaw to gain
    write access to otherwise read-only memory mappings and
    thus increase their privileges on the system.
    (CVE-2016-5195, Important)

  - It was found that stacking a file system over procfs in
    the Linux kernel could lead to a kernel stack overflow
    due to deep nesting, as demonstrated by mounting
    ecryptfs over procfs and creating a recursion by mapping
    /proc/environ. An unprivileged, local user could
    potentially use this flaw to escalate their privileges
    on the system. (CVE-2016-1583, Important)

Bug Fix(es) :

  - In some cases, a kernel crash or file system corruption
    occurred when running journal mode 'ordered'. The kernel
    crash was caused by a NULL pointer dereference due to a
    race condition between two journal functions. The file
    system corruption occurred due to a race condition
    between the do_get_write_access() function and buffer
    writeout. This update fixes both race conditions. As a
    result, neither the kernel crash, nor the file system
    corruption now occur.

  - Prior to this update, some Global File System 2 (GFS2)
    files had incorrect time stamp values due to two
    problems with handling time stamps of such files. The
    first problem concerned the atime time stamp, which
    ended up with an arbitrary value ahead of the actual
    value, when a GFS2 file was accessed. The second problem
    was related to the mtime and ctime time stamp updates,
    which got lost when a GFS2 file was written to from one
    node and read from or written to from another node. With
    this update, a set of patches has been applied that fix
    these problems. As a result, the time stamps of GFS2
    files are now handled correctly."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1610&L=scientific-linux-errata&F=&S=&P=6706
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67235ca4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/31");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-416.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-416.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
