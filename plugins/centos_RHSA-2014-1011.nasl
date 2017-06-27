#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1011 and 
# CentOS Errata and Security Advisory 2014:1011 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77031);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/21 14:15:32 $");

  script_cve_id("CVE-2014-3490");
  script_bugtraq_id(69058);
  script_xref(name:"RHSA", value:"2014:1011");

  script_name(english:"CentOS 7 : resteasy-base (CESA-2014:1011)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated resteasy-base packages that fix one security issue are now
available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

RESTEasy contains a JBoss project that provides frameworks to help
build RESTful Web Services and RESTful Java applications. It is a
fully certified and portable implementation of the JAX-RS
specification.

It was found that the fix for CVE-2012-0818 was incomplete: external
parameter entities were not disabled when the
resteasy.document.expand.entity.references parameter was set to false.
A remote attacker able to send XML requests to a RESTEasy endpoint
could use this flaw to read files accessible to the user running the
application server, and potentially perform other more advanced XXE
attacks. (CVE-2014-3490)

This issue was discovered by David Jorm of Red Hat Product Security.

All resteasy-base users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-August/020469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2ebdeb6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected resteasy-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxrs-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxrs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-providers-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-tjws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-atom-provider-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jackson-provider-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-javadoc-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxb-provider-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxrs-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxrs-all-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxrs-api-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jettison-provider-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-providers-pom-2.3.5-3.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-tjws-2.3.5-3.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
