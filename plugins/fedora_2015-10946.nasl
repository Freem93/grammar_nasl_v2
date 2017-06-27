#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-10946.
#

include("compat.inc");

if (description)
{
  script_id(84749);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:49:05 $");

  script_xref(name:"FEDORA", value:"2015-10946");

  script_name(english:"Fedora 22 : openvas-cli-1.4.1-2.fc22 / openvas-libraries-8.0.3-2.fc22 / openvas-manager-6.0.3-4.fc22 / etc (2015-10946)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bump to openvas8 because of the issues found in previous versions.
This should be the first version with scanner really working on
Fedora.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1169170"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a89eceb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed07f3bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a01b0cc4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e88004f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-scanner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"openvas-cli-1.4.1-2.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"openvas-libraries-8.0.3-2.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"openvas-manager-6.0.3-4.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"openvas-scanner-5.0.3-5.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvas-cli / openvas-libraries / openvas-manager / openvas-scanner");
}
