#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0329.
#

include("compat.inc");

if (description)
{
  script_id(51649);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2010-4645");
  script_osvdb_id(70370);
  script_xref(name:"FEDORA", value:"2011-0329");

  script_name(english:"Fedora 14 : maniadrive-1.2-26.fc14.1 / maniadrive-data-1.2-5.fc14 / php-5.3.5-1.fc14 / etc (2011-0329)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release resolves a critical issue, reported as PHP bug #53632 and
CVE-2010-4645, where conversions from string to double might cause the
PHP interpreter to hang on systems using x87 FPU registers.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=667806"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a51abfc8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f5435cf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b8c4678"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d558bb5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"maniadrive-1.2-26.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"maniadrive-data-1.2-5.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"php-5.3.5-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"php-eaccelerator-0.9.6.1-4.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / maniadrive-data / php / php-eaccelerator");
}
