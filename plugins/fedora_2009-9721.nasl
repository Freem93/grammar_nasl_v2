#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9721.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(41017);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/21 22:57:46 $");

  script_xref(name:"FEDORA", value:"2009-9721");

  script_name(english:"Fedora 11 : drupal-6.14-1.fc11 (2009-9721)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes SA-CORE-2009-008 http://drupal.org/node/579482 Remember to log
in to your site as the admin user before upgrading this package. After
upgrading the package, browse to http://host/drupal/update.php to run
the upgrade script. Multiple vulnerabilities and weaknesses were
discovered in Drupal. OpenID association cross site request forgeries
The OpenID module in Drupal 6 allows users to create an account or log
into a Drupal site using one or more OpenID identities. The core
OpenID module does not correctly implement Form API for the form that
allows one to link user accounts with OpenID identifiers. A malicious
user is therefore able to use cross site request forgeries to add
attacker controlled OpenID identities to existing accounts. These
OpenID identities can then be used to gain access to the affected
accounts. This issue affects Drupal 6.x only. OpenID impersonation The
OpenID module is not a compliant implementation of the OpenID
Authentication 2.0 specification. An implementation error allows a
user to access the account of another user when they share the same
OpenID 2.0 provider. This issue affects Drupal 6.x only. File upload
File uploads with certain extensions are not correctly processed by
the File API. This may lead to the creation of files that are
executable by Apache. The .htaccess that is saved into the files
directory by Drupal should normally prevent execution. The files are
only executable when the server is configured to ignore the directives
in the .htaccess file. This issue affects Drupal 6.x only. Session
fixation Drupal doesn't regenerate the session ID when an anonymous
user follows the one time login link used to confirm email addresses
and reset forgotten passwords. This enables a malicious user to fix
and reuse the session id of a victim under certain circumstances. This
issue affects Drupal 5.x only. Versions affected * Drupal 6.x before
version 6.14. * Drupal 5.x before version 5.20. Solution Install the
latest version: * If you are running Drupal 6.x then upgrade to Drupal
6.14.

  - If you are running Drupal 5.x then upgrade to Drupal
    5.20. If you are unable to upgrade immediately, you can
    apply a patch to secure your installation until you are
    able to do a proper upgrade. Theses patches fix the
    security vulnerabilities, but do not contain other fixes
    which were released in Drupal 6.14 or Drupal 5.20. * To
    patch Drupal 6.13 use SA- CORE-2009-008-6.13.patch. * To
    patch Drupal 5.19 use SA- CORE-2009-008-5.19.patch.
    Important note: Some users using OpenID might not be
    able to use the existing OpenID associations to login
    after the upgrade. These users should use the one time
    login via password recovery to get access to their user
    account and re-add desired associations. These users
    likely had issues with OpenID logins prior to the
    upgrade. Reported by The session fixation issue was
    reported by Noel Sharpe. OpenID impersonation was
    reported by Robert Metcalf. OpenID association CSRF was
    reported by Heine Deelstra (*). The file upload issue
    was reported by Heine Deelstra (*). (*) Member of the
    Drupal security team Fixed by The session fixation issue
    was fixed by Jakub Suchy. The OpenID and file upload
    issues were fixed by Heine Deelstra. Contact The
    security team for Drupal can be reached at security at
    drupal.org or via the form at http://drupal.org/contact.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/579482"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97542a39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"drupal-6.14-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal");
}
