#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-7575.
#

include("compat.inc");

if (description)
{
  script_id(54949);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:15:23 $");

  script_xref(name:"FEDORA", value:"2011-7575");

  script_name(english:"Fedora 15 : drupal7-7.2-1.fc15 (2011-7575)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CORE-2011-001

    - Project: Drupal core [1]

    - Version: 6.x, 7.x

    - Date: 2011-May-25

    - Security risk: Critical [2]

    - Exploitable from: Remote

    - Vulnerability: Access bypass, Cross Site Scripting

-------- DESCRIPTION

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=704319"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?541f8fb9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal7 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"drupal7-7.2-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal7");
}
