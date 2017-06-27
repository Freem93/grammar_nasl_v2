#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-14396.
#

include("compat.inc");

if (description)
{
  script_id(49165);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:13:51 $");

  script_xref(name:"FEDORA", value:"2010-14396");

  script_name(english:"Fedora 14 : sunbird-1.0-0.28.b2pre.fc14 / thunderbird-3.1.3-1.fc14 (2010-14396)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Thunderbird version 3.1.3, fixing multiple
security issues detailed in the upstream advisory:
http://www.mozilla.org/security
/known-vulnerabilities/thunderbird31.html#thunderbird3.1.3 Update also
includes sunbird package rebuilt against new version of Thunderbird.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/047355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7b31d6d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/047356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ba9abfc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sunbird and / or thunderbird packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sunbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC14", reference:"sunbird-1.0-0.28.b2pre.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"thunderbird-3.1.3-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sunbird / thunderbird");
}
