#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-e02ec160d8.
#

include("compat.inc");

if (description)
{
  script_id(96681);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/23 15:32:05 $");

  script_xref(name:"FEDORA", value:"2017-e02ec160d8");

  script_name(english:"Fedora 25 : wordpress (2017-e02ec160d8)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 4.7.1** Security and Maintenance Release

This is a security release for all previous versions and we strongly
encourage you to update your sites immediately.

WordPress versions 4.7 and earlier are affected by eight security
issues :

  - Remote code execution (RCE) in PHPMailer &ndash; No
    specific issue appears to affect WordPress or any of the
    major plugins we investigated but, out of an abundance
    of caution, we updated PHPMailer in this release. This
    issue was reported to PHPMailer by Dawid Golunski and
    Paul Buonopane.

  - The REST API exposed user data for all users who had
    authored a post of a public post type. WordPress 4.7.1
    limits this to only post types which have specified that
    they should be shown within the REST API. Reported by
    Krogsgard and Chris Jean.

  - Cross-site scripting (XSS) via the plugin name or
    version header on update-core.php. Reported by Dominik
    Schilling of the WordPress Security Team.

  - Cross-site request forgery (CSRF) bypass via uploading a
    Flash file. Reported by Abdullah Hussam.

  - Cross-site scripting (XSS) via theme name fallback.
    Reported by Mehmet Ince.

  - Post via email checks mail.example.com if default
    settings aren&rsquo;t changed. Reported by John
    Blackbourn of the WordPress Security Team.

  - A cross-site request forgery (CSRF) was discovered in
    the accessibility mode of widget editing. Reported by
    Ronnie Skansing.

  - Weak cryptographic security for multisite activation
    key. Reported by Jack.

Thank you to the reporters for practicing responsible disclosure.

In addition to the security issues above, WordPress 4.7.1 fixes 62
bugs from 4.7. For more information, see the [release
notes](https://codex.wordpress.org/Version_4.7.1) or consult the [list
of changes](https://core.trac.wordpress.org/query?milestone=4.7.1).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-e02ec160d8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codex.wordpress.org/Version_4.7.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://core.trac.wordpress.org/query?milestone=4.7.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"wordpress-4.7.1-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
