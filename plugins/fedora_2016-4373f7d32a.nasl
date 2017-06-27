#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-4373f7d32a.
#

include("compat.inc");

if (description)
{
  script_id(92987);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/08/17 14:24:38 $");

  script_cve_id("CVE-2016-3696", "CVE-2016-3704");
  script_xref(name:"FEDORA", value:"2016-4373f7d32a");

  script_name(english:"Fedora 24 : pulp / pulp-docker / pulp-ostree / pulp-puppet / pulp-python / etc (2016-4373f7d32a)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"2.8.6 is a security and bugfix release.

Included in the list of fixed issues in 2.8.5 are two CVEs :

  - CVE-2016-3696: Leakage of CA key in pulp-qpid-ssl-cfg

  - CVE-2016-3704: Unsafe use of bash $RANDOM for NSS DB
    password and seed

Several issues with database migrations are also addressed in this
release.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-4373f7d32a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulp-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulp-ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulp-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulp-rpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"pulp-2.8.6-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"pulp-docker-2.0.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"pulp-ostree-1.1.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"pulp-puppet-2.8.6-2.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"pulp-python-1.1.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"pulp-rpm-2.8.6-2.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pulp / pulp-docker / pulp-ostree / pulp-puppet / pulp-python / etc");
}
