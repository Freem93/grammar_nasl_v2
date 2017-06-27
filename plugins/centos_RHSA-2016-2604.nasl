#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2604 and 
# CentOS Errata and Security Advisory 2016:2604 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95350);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/11/28 15:05:43 $");

  script_cve_id("CVE-2016-7050");
  script_osvdb_id(144792);
  script_xref(name:"RHSA", value:"2016:2604");

  script_name(english:"CentOS 7 : resteasy-base (CESA-2016:2604)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for resteasy-base is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

RESTEasy contains a JBoss project that provides frameworks to help
build RESTful Web Services and RESTful Java applications. It is a
fully certified and portable implementation of the JAX-RS
specification.

Security Fix(es) :

* It was discovered that under certain conditions RESTEasy could be
forced to parse a request with SerializableProvider, resulting in
deserialization of potentially untrusted data. An attacker could
possibly use this flaw to execute arbitrary code with the permissions
of the application using RESTEasy. (CVE-2016-7050)

Red Hat would like to thank Mikhail Egorov (Odin) for reporting this
issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003652.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d22cbd9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected resteasy-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxrs-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jaxrs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-providers-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-resteasy-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy-base-tjws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-atom-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-client-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jackson-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-javadoc-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxb-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxrs-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxrs-all-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jaxrs-api-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-jettison-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-providers-pom-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-resteasy-pom-3.0.6-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"resteasy-base-tjws-3.0.6-4.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
