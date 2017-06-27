#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-4650.
#

include("compat.inc");

if (description)
{
  script_id(58698);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:44:21 $");

  script_xref(name:"FEDORA", value:"2012-4650");

  script_name(english:"Fedora 17 : pidgin-2.10.2-1.fc17 (2012-4650)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"version 2.10.2 (03/14/2012)

View all closed tickets for this release.

General: Fix compilation when using binutils 2.22 and new GDK pixbuf.
(#14799) Fix compilation of the MXit protocol plugin with GLib 2.31.
(#14773) 

Pidgin: Add support for the GNOME3 Network dialog. (#13882)
Fix rare crash. (#14392) Add support for the GNOME3 Default
Application dialog for configuring the Browser. 

libpurple: Support new connection states and signals for
NetworkManager 0.9+. (Dan Williams) (#13859) 

AIM and ICQ: Fix a possible crash when receiving an
unexpected message from the server. (Thijs Alkemade)
(#14983) Allow signing on with usernames containing periods
and underscores. (#13500) Allow adding buddies containing
periods and underscores. (#13500) Don't try to format ICQ
usernames entered as email addresses. Gets rid of an 'Unable
to format username' error at login. (#13883) 

MSN: Fix possible crashes caused by not validating incoming
messages as UTF-8. (Thijs Alkemade) (#14884) Support new
protocol version MSNP18. (#14753) Fix messages to offline
contacts. (#14302) 

Windows-Specific Changes: Fix the installer downloading of
spell-checking dictionaries (#14612) Fix compilation of the
Bonjour protocol plugin. (#14802) 

Plugins: The autoaccept plugin will no longer reset the
preference for unknown buddies to 'Auto Reject' in certain
cases. (#14964)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=803293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=803299"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-April/077282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71ed6b8e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"pidgin-2.10.2-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
