#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-11261.
#

include("compat.inc");

if (description)
{
  script_id(84902);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:49:05 $");

  script_xref(name:"FEDORA", value:"2015-11261");

  script_name(english:"Fedora 22 : php-horde-Horde-Auth-2.1.10-1.fc22 / php-horde-Horde-Core-2.20.6-1.fc22 / etc (2015-11261)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Horde_Form 2.0.10**

  - [jan] SECURITY: Fixed XSS in form renderer.

**Horde_Icalendar 2.1.1**

  - [jan] Fix generated VALARM TRIGGER attributes with empty
    duration (Ralf Becker).

**Horde_Auth 2.1.10**

  - [jan] SECURITY: Don't allow to login to LDAP with an
    emtpy password.

**Horde_Core 2.20.6**

  - [jan] SECURITY: Don't allow to login with an emtpy
    password.

    - [jan] Give administrators access to all groups, even
      with $conf['share']['any_group'] disabled.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?348b46d1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8e53e73"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36bcbc85"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162285.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebaf50fa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-Horde-Auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-Horde-Core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-Horde-Form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-Horde-Icalendar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");
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
if (rpm_check(release:"FC22", reference:"php-horde-Horde-Auth-2.1.10-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"php-horde-Horde-Core-2.20.6-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"php-horde-Horde-Form-2.0.10-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"php-horde-Horde-Icalendar-2.1.1-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-horde-Horde-Auth / php-horde-Horde-Core / php-horde-Horde-Form / etc");
}
