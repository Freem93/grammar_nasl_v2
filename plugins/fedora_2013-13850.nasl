#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-13850.
#

include("compat.inc");

if (description)
{
  script_id(69248);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_xref(name:"FEDORA", value:"2013-13850");

  script_name(english:"Fedora 19 : ReviewBoard-1.7.12-1.fc19 / python-djblets-0.7.16-1.fc19 (2013-13850)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"As with all ReviewBoard updates, you will need to run 'rb-site upgrade
/path/to/site' for all installed sites after applying this update.

== Action Required ==

The default Apache configuration is now more strict with how it serves
up file attachments. This does not apply to existing installations.
See
http://support.beanbaginc.com/support/solutions/articles/110173-securi
ng-file-attachments for details.

== Description ==

  - New upstream release 1.7.12

    -
      http://www.reviewboard.org/docs/releasenotes/reviewboa
      rd/1.7.12/

    - Security Fixes :

    - Function names in diff headers are no longer rendered
      as HTML.

    - If a user's full name contained HTML, the Submitters
      list would render it as HTML, without escaping it.
      This was an XSS vulnerability.

    - The default Apache configuration is now more strict
      with how it serves up file attachments. This does not
      apply to existing installations. See
      http://support.beanbaginc.com/support/solutions/articl
      es/110173-securing-file-attachments for details.

    - Uploaded files are now renamed to include a hash,
      preventing users from uploading malicious filenames,
      and making filenames unguessable.

    - Recaptcha support has been updated to use the new URLs
      provided by Google.

    - New Features :

    - Added a X-ReviewRequest-Repository header for e-mails.

    - Extension Improvements :

    - Extensions can now specify their list of app
      directories.

    - Extensions can now specify the author's URL.

    - Improved the look and feel for extension
      configuration.

    - Improved the functionality for extension
      configuration.

    - Improved the list of available extensions.

    - Bug Fixes :

    - Fixed the 'Show Whitespace Changes' toggle.

    - Fixed compatibility with modern versions of
      django-storages.

    - Draft comments on file attachments are no longer shown
      to all users.

    - Fixed issues with console windows appearing when
      invoking Clear Case requests on Python 2.7.x and
      Windows 7.

    - Review requests on Local Sites are now guaranteed to
      have the proper ID.

    - Fixed starring review requests on Local Sites.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://support.beanbaginc.com/support/solutions/articles/110173-securing-file-attachments
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2c5459f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.reviewboard.org/docs/releasenotes/reviewboard/1.7.12/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baf4e775"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113484.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d636bb98"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ReviewBoard and / or python-djblets packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ReviewBoard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-djblets");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"ReviewBoard-1.7.12-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"python-djblets-0.7.16-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ReviewBoard / python-djblets");
}
