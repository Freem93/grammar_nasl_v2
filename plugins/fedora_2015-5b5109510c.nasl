#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5b5109510c.
#

include("compat.inc");

if (description)
{
  script_id(89249);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_xref(name:"FEDORA", value:"2015-5b5109510c");

  script_name(english:"Fedora 22 : firefox-42.0-2.fc22 / nspr-4.10.10-1.fc22 / nss-3.20.1-1.0.fc22 / etc (2015-5b5109510c)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"firefox-42.0-2.fc22 - Update to 42.0 firefox-42.0-2.fc21 - Update to
42.0 firefox-42.0-2.fc23 - Update to 42.0 nspr-4.10.10-1.fc23 - Update
to NSPR_4_10_10_RTM nspr-4.10.10-1.fc21 - Update to NSPR_4_10_10_RTM
nspr-4.10.10-1.fc22 - Update to NSPR_4_10_10_RTM

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f67d894"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?111a164b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3520f4e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a8a7e6e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?622adab2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"firefox-42.0-2.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"nspr-4.10.10-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"nss-3.20.1-1.0.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"nss-softokn-3.20.1-1.0.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"nss-util-3.20.1-1.0.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / nspr / nss / nss-softokn / nss-util");
}
