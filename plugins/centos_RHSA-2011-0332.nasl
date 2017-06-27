#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0332 and 
# CentOS Errata and Security Advisory 2011:0332 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53426);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:51:59 $");

  script_cve_id("CVE-2011-0001");
  script_osvdb_id(74916);
  script_xref(name:"RHSA", value:"2011:0332");

  script_name(english:"CentOS 5 : scsi-target-utils (CESA-2011:0332)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated scsi-target-utils package that fixes one security issue is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The scsi-target-utils package contains the daemon and tools to set up
and monitor SCSI targets. Currently, iSCSI software and iSER targets
are supported.

A double-free flaw was found in scsi-target-utils' tgtd daemon. A
remote attacker could trigger this flaw by sending carefully-crafted
network traffic, causing the tgtd daemon to crash. (CVE-2011-0001)

Red Hat would like to thank Emmanuel Bouillon of NATO C3 Agency for
reporting this issue.

All scsi-target-utils users should upgrade to this updated package,
which contains a backported patch to correct this issue. All running
scsi-target-utils services must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017393.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30a17a89"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017394.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc4d4d8b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected scsi-target-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:scsi-target-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"scsi-target-utils-1.0.8-0.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
