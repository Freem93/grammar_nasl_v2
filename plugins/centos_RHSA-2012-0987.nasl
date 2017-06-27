#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0987 and 
# CentOS Errata and Security Advisory 2012:0987 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59935);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2012-2328");
  script_osvdb_id(104203);
  script_xref(name:"RHSA", value:"2012:0987");

  script_name(english:"CentOS 6 : sblim-cim-client2 (CESA-2012:0987)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sblim-cim-client2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The SBLIM (Standards-Based Linux Instrumentation for Manageability)
CIM (Common Information Model) Client is a class library for Java
applications that provides access to CIM servers using the CIM
Operations over HTTP protocol defined by the DMTF (Distributed
Management Task Force) standards.

It was found that the Java HashMap implementation was susceptible to
predictable hash collisions. SBLIM uses HashMap when parsing XML
inputs. A specially crafted CIM-XML message from a WBEM (Web-Based
Enterprise Management) server could cause a SBLIM client to use an
excessive amount of CPU. Randomization has been added to help avoid
collisions. (CVE-2012-2328)

All users of sblim-cim-client2 are advised to upgrade to these updated
packages, which contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a825e0ef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sblim-cim-client2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cim-client2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cim-client2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cim-client2-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
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
if (rpm_check(release:"CentOS-6", reference:"sblim-cim-client2-2.1.3-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sblim-cim-client2-javadoc-2.1.3-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sblim-cim-client2-manual-2.1.3-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
