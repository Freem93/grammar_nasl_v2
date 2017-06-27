#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-6999afd53e.
#

include("compat.inc");

if (description)
{
  script_id(89265);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:58 $");

  script_xref(name:"FEDORA", value:"2015-6999afd53e");

  script_name(english:"Fedora 21 : webkitgtk-2.4.9-2.fc21 / webkitgtk3-2.4.9-2.fc21 (2015-6999afd53e)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"webkitgtk-2.4.9-2.fc21 - rhbz#1189303 - [abrt] midori:
WebCore::SQLiteStatement::prepare(): midori killed by SIGSEGV
Initialize string in SQLiteStatement before using it
webkitgtk-2.4.9-2.fc22 - rhbz#1189303 - [abrt] midori:
WebCore::SQLiteStatement::prepare(): midori killed by SIGSEGV
Initialize string in SQLiteStatement before using it
webkitgtk-2.4.9-3.fc23 - rhbz#1189303 - [abrt] midori:
WebCore::SQLiteStatement::prepare(): midori killed by SIGSEGV
Initialize string in SQLiteStatement before using it
webkitgtk3-2.4.9-2.fc21 - rhbz#1189303 - [abrt] midori:
WebCore::SQLiteStatement::prepare(): midori killed by SIGSEGV
Initialize string in SQLiteStatement before using it
webkitgtk3-2.4.9-2.fc22 - rhbz#1189303 - [abrt] midori:
WebCore::SQLiteStatement::prepare(): midori killed by SIGSEGV
Initialize string in SQLiteStatement before using it
webkitgtk3-2.4.9-3.fc23 - rhbz#1189303 - [abrt] midori:
WebCore::SQLiteStatement::prepare(): midori killed by SIGSEGV
Initialize string in SQLiteStatement before using it

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1189303"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-October/168774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?795fcf05"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-October/168775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fa7d562"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk and / or webkitgtk3 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/05");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"webkitgtk-2.4.9-2.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"webkitgtk3-2.4.9-2.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk / webkitgtk3");
}
