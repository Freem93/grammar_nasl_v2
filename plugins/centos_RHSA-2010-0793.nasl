#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0793 and 
# CentOS Errata and Security Advisory 2010:0793 respectively.
#

include("compat.inc");

if (description)
{
  script_id(50798);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2010-3856");
  script_bugtraq_id(44347);
  script_osvdb_id(68920);
  script_xref(name:"RHSA", value:"2010:0793");

  script_name(english:"CentOS 5 : glibc (CESA-2010:0793)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

It was discovered that the glibc dynamic linker/loader did not perform
sufficient safety checks when loading dynamic shared objects (DSOs) to
provide callbacks for its auditing API during the execution of
privileged programs. A local attacker could use this flaw to escalate
their privileges via a carefully-chosen system DSO library containing
unsafe constructors. (CVE-2010-3856)

Red Hat would like to thank Ben Hawkes and Tavis Ormandy for reporting
this issue.

All users should upgrade to these updated packages, which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b7dc34b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08881263"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"glibc-2.5-49.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-common-2.5-49.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-devel-2.5-49.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-headers-2.5-49.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-utils-2.5-49.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nscd-2.5-49.el5_5.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");