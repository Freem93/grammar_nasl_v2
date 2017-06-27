#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-46fcfd8c98.
#

include("compat.inc");

if (description)
{
  script_id(100437);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/26 15:15:35 $");

  script_xref(name:"FEDORA", value:"2017-46fcfd8c98");

  script_name(english:"Fedora 24 : wordpress (2017-46fcfd8c98)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 4.7.5** is now available. This is a security release for
all previous versions and we strongly encourage you to update your
sites immediately.

WordPress versions 4.7.4 and earlier are affected by six security
issues :

  - Insufficient redirect validation in the HTTP class.
    Reported by Ronni Skansing.

  - Improper handling of post meta data values in the
    XML-RPC API. Reported by Sam Thomas.

  - Lack of capability checks for post meta data in the
    XML-RPC API. Reported by Ben Bidner of the WordPress
    Security Team.

  - A Cross Site Request Forgery (CRSF) vulnerability was
    discovered in the filesystem credentials dialog.
    Reported by Yorick Koster.

  - A cross-site scripting (XSS) vulnerability was
    discovered when attempting to upload very large files.
    Reported by Ronni Skansing.

  - A cross-site scripting (XSS) vulnerability was
    discovered related to the Customizer. Reported by Weston
    Ruter of the WordPress Security Team.

Thank you to the reporters of these issues for practicing responsible
disclosure.

In addition to the security issues above, WordPress 4.7.5 contains 3
maintenance fixes to the 4.7 release series. For more information, see
the [release notes](https://codex.wordpress.org/Version_4.7.5) or
consult the [list of
changes](https://core.trac.wordpress.org/query?status=closed&milestone
=4.7.5&group=component&col=id&col=summary&col=component&col=status&col
=owner&col=type&col=priority&col=keywords&order=priority).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-46fcfd8c98"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codex.wordpress.org/Version_4.7.5"
  );
  # https://core.trac.wordpress.org/query?status=closed&milestone=4.7.5&group=component&col=id&col=summary&col=component&col=status&col=owner&col=type&col=priority&col=keywords&order=priority
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78be042d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"wordpress-4.7.5-1.fc24")) flag++;


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


