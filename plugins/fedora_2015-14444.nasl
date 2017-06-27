#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-14444.
#

include("compat.inc");

if (description)
{
  script_id(85825);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2015/11/01 04:40:10 $");

  script_cve_id("CVE-2015-6658", "CVE-2015-6659", "CVE-2015-6660", "CVE-2015-6661", "CVE-2015-6665");
  script_xref(name:"FEDORA", value:"2015-14444");

  script_name(english:"Fedora 22 : drupal6-6.37-1.fc22 (2015-14444)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Maintenance and security release of the Drupal 6 series. This release
fixes **security vulnerabilities**. Sites are [urged to upgrade
immediately](https://www.drupal.org/node/1494290) after reading the
notes below and the security announcement: [Drupal Core - Critical -
Multiple Vulnerabilities -
SA-CORE-2015-003](https://www.drupal.org/SA-CORE-2015-003) No other
fixes are included. No changes have been made to the .htaccess,
robots.txt or default settings.php files in this release, so upgrading
custom versions of those files is not necessary. #### Known issues:
None. #### Major changes since 6.36: * For security reasons, the
autocomplete system now makes Ajax requests to non-clean URLs only,
although protection is also in place for custom code that does so
using clean URLs. There is a new form API #process function on
autocomplete-enabled text fields that is required for the autocomplete
functionality to work; custom and contributed modules should ensure
that they are not overriding this #process function accidentally when
altering text fields on forms. Part of the security fix also includes
changes to theme_textfield(); it is recommended that sites which
override this theme function make those changes as well (see the
theme_textfield section of this diff for details). * When form API
token validation fails (for example, when a cross-site request forgery
attempt is detected, or a user tries to submit a form after having
logged out and back in again in the meantime), the form API now skips
calling form element value callbacks, except for a select list of
callbacks provided by Drupal core that are known to be safe. In rare
cases, this could lead to data loss when a user submits a form and
receives a token validation error, but the overall effect is expected
to be minor.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255662"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-September/165690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1e271c6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/SA-CORE-2015-003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/node/1494290"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");
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
if (rpm_check(release:"FC22", reference:"drupal6-6.37-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal6");
}
