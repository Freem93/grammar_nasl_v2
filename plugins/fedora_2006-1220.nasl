#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1220.
#

include("compat.inc");

if (description)
{
  script_id(24052);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-1220");

  script_name(english:"Fedora Core 6 : cups-1.2.7-1.3.fc6 (2006-1220)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New version. This update also fixes a problem with printing to serial
printers, and an information leak issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-November/001015.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be013c19"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"cups-1.2.7-1.3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"cups-debuginfo-1.2.7-1.3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"cups-devel-1.2.7-1.3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"cups-libs-1.2.7-1.3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"cups-lpd-1.2.7-1.3.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-debuginfo / cups-devel / cups-libs / cups-lpd");
}
