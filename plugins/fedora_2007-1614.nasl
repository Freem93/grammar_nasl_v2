#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-1614.
#

include("compat.inc");

if (description)
{
  script_id(27724);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:54 $");

  script_cve_id("CVE-2007-3387");
  script_xref(name:"FEDORA", value:"2007-1614");

  script_name(english:"Fedora 7 : koffice-1.6.3-9.fc7 (2007-1614)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to address a stack-based buffer overflow
vulnerability in kword's pdf filter.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-August/003242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd17ba6b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kchart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kexi-driver-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kexi-driver-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-suite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"koffice-core-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-debuginfo-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-devel-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-filters-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-karbon-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kchart-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kexi-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kexi-driver-mysql-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kexi-driver-pgsql-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kformula-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kivio-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kplato-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kpresenter-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-krita-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kspread-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kugar-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kword-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-libs-1.6.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-suite-1.6.3-9.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "koffice-core / koffice-debuginfo / koffice-devel / koffice-filters / etc");
}
