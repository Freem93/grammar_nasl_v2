#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1587. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63901);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2009-2695", "CVE-2009-3547");
  script_bugtraq_id(36901);
  script_xref(name:"RHSA", value:"2009:1587");

  script_name(english:"RHEL 5 : kernel (RHSA-2009:1587)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and various
bugs are now available for Red Hat Enterprise Linux 5.3 Extended
Update Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* a system with SELinux enforced was more permissive in allowing local
users in the unconfined_t domain to map low memory areas even if the
mmap_min_addr restriction was enabled. This could aid in the local
exploitation of NULL pointer dereference bugs. (CVE-2009-2695,
Important)

* a NULL pointer dereference flaw was found in each of the following
functions in the Linux kernel: pipe_read_open(), pipe_write_open(),
and pipe_rdwr_open(). When the mutex lock is not held, the i_pipe
pointer could be released by other processes before it is used to
update the pipe's reader and writer counters. This could lead to a
local denial of service or privilege escalation. (CVE-2009-3547,
Important)

This update also fixes the following bugs :

* a caching bug in nfs_readdir() has been resolved. This may have
caused parts of directory listings to become stale, as they came from
cached data when they should not have, possibly causing NFS clients to
see duplicate files or not see all files in a directory. (BZ#526959)

* a bug prevented the pciehp driver from detecting PCI Express hot
plug slots on some systems. (BZ#530381)

* when a process attempted to read from a page that had first been
accessed by writing to part of it (via write(2)), the NFS client
needed to flush the modified portion of the page out to the server,
and then read the entire page back in. This flush caused performance
issues. (BZ#521243)

* a deadlock was found in the cciss driver. In rare cases, this caused
an NMI lockup during boot. Messages such as 'cciss: controller
cciss[x] failed, stopping.' and 'cciss[x]: controller not responding.'
may have been displayed on the console. (BZ#525728)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2695.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-18042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1587.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", reference:"kernel-doc-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"kernel-headers-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-devel-2.6.18-128.11.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-128.11.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
