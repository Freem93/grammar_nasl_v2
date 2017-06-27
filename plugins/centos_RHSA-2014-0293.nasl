#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0293 and 
# CentOS Errata and Security Advisory 2014:0293 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72988);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/17 10:44:21 $");

  script_cve_id("CVE-2014-0004");
  script_bugtraq_id(66081);
  script_xref(name:"RHSA", value:"2014:0293");

  script_name(english:"CentOS 6 : udisks (CESA-2014:0293)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated udisks packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The udisks package provides a daemon, a D-Bus API, and command line
utilities for managing disks and storage devices.

A stack-based buffer overflow flaw was found in the way udisks handled
files with long path names. A malicious, local user could use this
flaw to create a specially crafted directory structure that, when
processed by the udisks daemon, could lead to arbitrary code execution
with the privileges of the udisks daemon (root). (CVE-2014-0004)

This issue was discovered by Florian Weimer of the Red Hat Product
Security Team.

All udisks users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020200.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d9e5dfd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected udisks packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:udisks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:udisks-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:udisks-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"udisks-1.0.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"udisks-devel-1.0.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"udisks-devel-docs-1.0.1-7.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
