#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1463 and 
# CentOS Errata and Security Advisory 2009:1463 respectively.
#

include("compat.inc");

if (description)
{
  script_id(41627);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2009-2905");
  script_bugtraq_id(36515);
  script_osvdb_id(58330);
  script_xref(name:"RHSA", value:"2009:1463");

  script_name(english:"CentOS 3 / 4 / 5 : newt (CESA-2009:1463)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated newt packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Newt is a programming library for color text mode, widget-based user
interfaces. Newt can be used to add stacked windows, entry widgets,
checkboxes, radio buttons, labels, plain text fields, scrollbars, and
so on, to text mode user interfaces.

A heap-based buffer overflow flaw was found in the way newt processes
content that is to be displayed in a text dialog box. A local attacker
could issue a specially crafted text dialog box display request
(direct or via a custom application), leading to a denial of service
(application crash) or, potentially, arbitrary code execution with the
privileges of the user running the application using the newt library.
(CVE-2009-2905)

Users of newt should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing the updated
packages, all applications using the newt library must be restarted
for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016256.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d04a1c1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016257.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd9fa340"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d647958b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?343ee173"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b20c4df"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af03142d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected newt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:newt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:newt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"newt-0.51.5-2.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"newt-0.51.5-2.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"newt-devel-0.51.5-2.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"newt-devel-0.51.5-2.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"newt-0.51.6-10.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"newt-0.51.6-10.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"newt-debuginfo-0.51.6-10.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"newt-devel-0.51.6-10.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"newt-devel-0.51.6-10.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"newt-0.52.2-12.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"newt-devel-0.52.2-12.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
