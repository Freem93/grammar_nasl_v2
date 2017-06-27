#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-17399.
#

include("compat.inc");

if (description)
{
  script_id(57622);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:05:52 $");

  script_xref(name:"FEDORA", value:"2011-17399");

  script_name(english:"Fedora 15 : firefox-9.0.1-1.fc15 / gnome-python2-extras-2.25.3-35.fc15.4 / nspr-4.8.9-2.fc15 / etc (2011-17399)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest version of Firefox and Thunderbird have the following
changes :

  - Added Type Inference, significantly improving JavaScript
    performance

    - Added support for querying Do Not Track status via
      JavaScript

    - Added support for font-stretch

    - Improved support for text-overflow

    - Improved standards support for HTML5, MathML, and CSS

    - Fixed several stability issues

    - Fixed several security issues

Notable nss changes include :

1. SSL 2.0 is disabled by default.

2. A defense against the SSL 3.0 and TLS 1.0 CBC chosen plaintext
attack demonstrated by Rizzo and Duong (CVE-2011-3389) is enabled by
default. Set the SSL_CBC_RANDOM_IV SSL option to PR_FALSE to disable
it.

3. SHA-224 is supported.

4. Added PORT_ErrorToString and PORT_ErrorToName to return the error
message and symbolic name of an NSS error code.

5. Added NSS_GetVersion to return the NSS version string.

6. Added experimental support of RSA-PSS to the softoken only
(contributed by Hanno Bock, http://rsapss.hboeck.de/).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rsapss.hboeck.de/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47ee3616"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12cc855e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bf1b5d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c745d9a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?648a9ef9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ab134ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2aa50f32"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f1fb28a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e3ea6b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072231.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a402c324"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/23");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"firefox-9.0.1-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gnome-python2-extras-2.25.3-35.fc15.4")) flag++;
if (rpm_check(release:"FC15", reference:"nspr-4.8.9-2.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"nss-3.13.1-10.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"nss-softokn-3.13.1-15.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"nss-util-3.13.1-3.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"perl-Gtk2-MozEmbed-0.09-1.fc15.8")) flag++;
if (rpm_check(release:"FC15", reference:"thunderbird-9.0-4.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"thunderbird-lightning-1.1-0.1.rc1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"xulrunner-9.0.1-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / gnome-python2-extras / nspr / nss / nss-softokn / etc");
}
