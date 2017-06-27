#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-3446.
#

include("compat.inc");

if (description)
{
  script_id(73035);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:32:17 $");

  script_xref(name:"FEDORA", value:"2014-3446");

  script_name(english:"Fedora 20 : ReviewBoard-1.7.22-2.fc20 (2014-3446)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - New upstream security release 1.7.22

    -
      http://www.reviewboard.org/docs/releasenotes/reviewboa
      rd/1.7.22/

    - Security Fixes :

    - An XSS vulnerability was found in the Search field's
      auto-complete.

    - New Features :

    - Added support for anonymous access to public Local
      Sites.

    - Added support for parallel-installed versions of
      Django.

    - API Changes :

    - The documentation for Review Group Resource no longer
      says that review groups cannot be created through the
      API.

    - Bug Fixes :

    - Install/Upgrade :

    - Fixed compatibility with Apache 2.4's method for
      authorization in newly generated config files.

    - Fixed an issue on some configurations where loading in
      initial schema data for the database would fail

    - rb-site upgrade --all-sites no longer throws an error
      if there are no valid sites configured.

    - Administration :

    - Administrators now have access to all repositories,
      instead of just public ones or ones they're a member
      of.

    - Repositories backed by paths that no longer exist can
      now be hidden.

    - Fixed creating groups and repositories that had
      conflicting 'unique' fields.

    - Password fields no longer appear blank when they have
      a value in forms.

    - Setting https in the server URL now properly marks the
      server as using HTTPS. All URLs generated for the API
      and e-mails will include https instead of http.

    - Fixed incorrect labelling for the review request
      status graph in the Admin dashboard.

    - LDAP :

    - Usernames, passwords, and other information are
      properly encoded to UTF-8 before authenticating.

    - Users without e-mail addresses in LDAP no longer break
      when first authenticating.

    - Dashboard :

    - Fixed support for accessing watched groups through the
      Dashboard.

    - Repositories :

    - Copied files in Git diffs no longer results in File
      Not Found errors, and properly handles showing the
      state much like moved files.

    - Added better compatibility with Mercurial repository
      when accessing hg-history URLs, when the server name
      didn't contain a trailing slash.

    - Added better CVS compatibility for repositories that
      don't contain CVSROOT/modules.

    - Fixed issues with Clear Case in multi-site mode when
      OIDs weren't yet available on the server.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.reviewboard.org/docs/releasenotes/reviewboard/1.7.22/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-March/130163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e45ee49"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ReviewBoard package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ReviewBoard");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"ReviewBoard-1.7.22-2.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ReviewBoard");
}
