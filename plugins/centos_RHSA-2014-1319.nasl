#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1319 and 
# CentOS Errata and Security Advisory 2014:1319 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77994);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/23 14:53:34 $");

  script_cve_id("CVE-2013-4002");
  script_bugtraq_id(61310);
  script_osvdb_id(95418);
  script_xref(name:"RHSA", value:"2014:1319");

  script_name(english:"CentOS 6 / 7 : xerces-j2 (CESA-2014:1319)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xerces-j2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Apache Xerces for Java (Xerces-J) is a high performance, standards
compliant, validating XML parser written in Java. The xerces-j2
packages provide Xerces-J version 2.

A resource consumption issue was found in the way Xerces-J handled XML
declarations. A remote attacker could use an XML document with a
specially crafted declaration using a long pseudo-attribute name that,
when parsed by an application using Xerces-J, would cause that
application to use an excessive amount of CPU. (CVE-2013-4002)

All xerces-j2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. Applications
using the Xerces-J must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26849bc2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08cd5471"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-j2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-2.7.1-12.7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-demo-2.7.1-12.7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-javadoc-apis-2.7.1-12.7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-javadoc-impl-2.7.1-12.7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-javadoc-other-2.7.1-12.7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-javadoc-xni-2.7.1-12.7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xerces-j2-scripts-2.7.1-12.7.el6_5")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-j2-2.11.0-17.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-j2-demo-2.11.0-17.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-j2-javadoc-2.11.0-17.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
