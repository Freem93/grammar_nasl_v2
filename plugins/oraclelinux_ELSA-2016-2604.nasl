#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2604 and 
# Oracle Linux Security Advisory ELSA-2016-2604 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94723);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/11 14:36:26 $");

  script_cve_id("CVE-2016-7050");
  script_osvdb_id(144792);
  script_xref(name:"RHSA", value:"2016:2604");

  script_name(english:"Oracle Linux 7 : resteasy-base (ELSA-2016-2604)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2604 :

An update for resteasy-base is now available for Red Hat Enterprise
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006495.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-jaxrs-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-jaxrs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-providers-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-resteasy-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy-base-tjws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-atom-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-client-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-jackson-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-javadoc-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-jaxb-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-jaxrs-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-jaxrs-all-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-jaxrs-api-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-jettison-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-providers-pom-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-resteasy-pom-3.0.6-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"resteasy-base-tjws-3.0.6-4.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "resteasy-base / resteasy-base-atom-provider / resteasy-base-client / etc");
}
