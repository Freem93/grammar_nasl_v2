#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0895 and 
# CentOS Errata and Security Advisory 2010:0895 respectively.
#

include("compat.inc");

if (description)
{
  script_id(50810);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/14 15:20:31 $");

  script_cve_id("CVE-2010-4170");
  script_osvdb_id(69489);
  script_xref(name:"RHSA", value:"2010:0895");

  script_name(english:"CentOS 4 : systemtap (CESA-2010:0895)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

SystemTap is an instrumentation system for systems running the Linux
kernel, version 2.6. Developers can write scripts to collect data on
the operation of the system. staprun, the SystemTap runtime tool, is
used for managing SystemTap kernel modules (for example, loading
them).

It was discovered that staprun did not properly sanitize the
environment before executing the modprobe command to load an
additional kernel module. A local, unprivileged user could use this
flaw to escalate their privileges. (CVE-2010-4170)

Note: On Red Hat Enterprise Linux 4, an attacker must be a member of
the stapusr group to exploit this issue. Also note that, after
installing this update, users already in the stapdev group must be
added to the stapusr group in order to be able to run the staprun
tool.

Red Hat would like to thank Tavis Ormandy for reporting this issue.

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-November/017187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?015e67f9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-November/017188.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74360cb7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"systemtap-0.6.2-2.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"systemtap-0.6.2-2.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"systemtap-runtime-0.6.2-2.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"systemtap-runtime-0.6.2-2.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"systemtap-testsuite-0.6.2-2.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"systemtap-testsuite-0.6.2-2.el4_8.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
