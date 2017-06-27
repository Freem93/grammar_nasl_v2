#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0831 and 
# CentOS Errata and Security Advisory 2013:0831 respectively.
#

include("compat.inc");

if (description)
{
  script_id(66485);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/09/27 11:01:50 $");

  script_cve_id("CVE-2013-1962");
  script_bugtraq_id(59937);
  script_osvdb_id(93451);
  script_xref(name:"RHSA", value:"2013:0831");

  script_name(english:"CentOS 6 : libvirt (CESA-2013:0831)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

It was found that libvirtd leaked file descriptors when listing all
volumes for a particular pool. A remote attacker able to establish a
read-only connection to libvirtd could use this flaw to cause libvirtd
to consume all available file descriptors, preventing other users from
using libvirtd services (such as starting a new guest) until libvirtd
is restarted. (CVE-2013-1962)

Red Hat would like to thank Edoardo Comar of IBM for reporting this
issue.

This update also fixes the following bugs :

* Previously, libvirt made control group (cgroup) requests on files
that it should not have. With older kernels, such nonsensical cgroup
requests were ignored; however, newer kernels are stricter, resulting
in libvirt logging spurious warnings and failures to the libvirtd and
audit logs. The audit log failures displayed by the ausearch tool were
similar to the following :

root [date] - failed cgroup allow path rw /dev/kqemu

With this update, libvirt no longer attempts the nonsensical cgroup
actions, leaving only valid attempts in the libvirtd and audit logs
(making it easier to search for real cases of failure). (BZ#958837)

* Previously, libvirt used the wrong variable when constructing audit
messages. This led to invalid audit messages, causing ausearch to
format certain entries as having 'path=(null)' instead of the correct
path. This could prevent ausearch from locating events related to
cgroup device ACL modifications for guests managed by libvirt. With
this update, the audit messages are generated correctly, preventing
loss of audit coverage. (BZ#958839)

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019732.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libvirt-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-client-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-devel-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-python-0.10.2-18.el6_4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
