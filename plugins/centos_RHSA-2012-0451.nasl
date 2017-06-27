#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0451 and 
# CentOS Errata and Security Advisory 2012:0451 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58584);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/22 14:13:26 $");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");
  script_bugtraq_id(52865);
  script_osvdb_id(81009, 81010, 81011);
  script_xref(name:"RHSA", value:"2012:0451");

  script_name(english:"CentOS 5 / 6 : rpm (CESA-2012:0451)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6; Red Hat Enterprise
Linux 3 and 4 Extended Life Cycle Support; Red Hat Enterprise Linux
5.3 Long Life; and Red Hat Enterprise Linux 5.6, 6.0 and 6.1 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The RPM Package Manager (RPM) is a command-line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

Multiple flaws were found in the way RPM parsed package file headers.
An attacker could create a specially crafted RPM package that, when
its package header was accessed, or during package signature
verification, could cause an application using the RPM library (such
as the rpm command line tool, or the yum and up2date package managers)
to crash or, potentially, execute arbitrary code. (CVE-2012-0060,
CVE-2012-0061, CVE-2012-0815)

Note: Although an RPM package can, by design, execute arbitrary code
when installed, this issue would allow a specially crafted RPM package
to execute arbitrary code before its digital signature has been
verified. Package downloads from the Red Hat Network are protected by
the use of a secure HTTPS connection in addition to the RPM package
signature checks.

All RPM users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running applications
linked against the RPM library must be restarted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?808dcae6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018550.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e11b51e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"popt-1.10.2.3-28.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-apidocs-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-build-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-devel-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-libs-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-python-4.4.2.3-28.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"rpm-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rpm-apidocs-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rpm-build-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rpm-cron-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rpm-devel-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rpm-libs-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rpm-python-4.8.0-19.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
