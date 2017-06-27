#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0675 and 
# CentOS Errata and Security Advisory 2010:0675 respectively.
#

include("compat.inc");

if (description)
{
  script_id(49203);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-2956");
  script_osvdb_id(67842);
  script_xref(name:"RHSA", value:"2010:0675");

  script_name(english:"CentOS 5 : sudo (CESA-2010:0675)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes one security issue is now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the way sudo handled Runas specifications
containing both a user and a group list. If a local user were
authorized by the sudoers file to perform their sudo commands with the
privileges of a specified user and group, they could use this flaw to
run those commands with the privileges of either an arbitrary user or
group on the system. (CVE-2010-2956)

Red Hat would like to thank Markus Wuethrich of Swiss Post -
PostFinance for reporting this issue.

Users of sudo should upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/016990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb74c025"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/016991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?899e8abf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"sudo-1.7.2p1-8.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
