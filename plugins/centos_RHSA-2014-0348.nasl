#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0348 and 
# CentOS Errata and Security Advisory 2014:0348 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73309);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2014-0107");
  script_bugtraq_id(66397);
  script_osvdb_id(104942);
  script_xref(name:"RHSA", value:"2014:0348");

  script_name(english:"CentOS 5 / 6 : xalan-j2 (CESA-2014:0348)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xalan-j2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Xalan-Java is an XSLT processor for transforming XML documents into
HTML, text, or other XML document types.

It was found that the secure processing feature of Xalan-Java had
insufficient restrictions defined for certain properties and features.
A remote attacker able to provide Extensible Stylesheet Language
Transformations (XSLT) content to be processed by an application using
Xalan-Java could use this flaw to bypass the intended constraints of
the secure processing feature. Depending on the components available
in the classpath, this could lead to arbitrary remote code execution
in the context of the application server running the application that
uses Xalan-Java. (CVE-2014-0107)

All xalan-j2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f28783e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0db082a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xalan-j2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xalan-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xalan-j2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xalan-j2-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xalan-j2-xsltc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xalan-j2-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xalan-j2-demo-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xalan-j2-javadoc-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xalan-j2-manual-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xalan-j2-xsltc-2.7.0-6jpp.2")) flag++;

if (rpm_check(release:"CentOS-6", reference:"xalan-j2-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xalan-j2-demo-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xalan-j2-javadoc-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xalan-j2-manual-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xalan-j2-xsltc-2.7.0-9.9.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
