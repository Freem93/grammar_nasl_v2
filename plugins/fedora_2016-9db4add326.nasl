#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-9db4add326.
#

include("compat.inc");

if (description)
{
  script_id(90658);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/22 15:34:21 $");

  script_xref(name:"FEDORA", value:"2016-9db4add326");

  script_name(english:"Fedora 24 : glpi-0.90.3-1.fc24 (2016-9db4add326)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 0.90.3** * security update to prevent a minor vulnerability
* fix issues with post-only ticket form See
[changelog](https://github.com/glpi-
project/glpi/issues?q=milestone:0.90.3) for more details. ----
**Version 0.90.2** Include bugfixes and some minor features : * An
alert in central page when some of your mysql tables are marked as
crashed * A better flexibility in splitted layout for small screens *
More fields in Search- engine (Document comments, ticket id for
Changes) * Redirect to previous page after a profile switching (when
it is possible) * An icon for default document type * A better
compatibility when collecting emails from office365 See
[changelog](https://github.com/glpi-project/glpi/issues?q=milestone:0.
90.2) This package also fix the logrotate configuration.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/glpi-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/glpi-project/glpi/issues?q=milestone:0.90.2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/182549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7234959"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glpi package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC24", reference:"glpi-0.90.3-1.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glpi");
}
