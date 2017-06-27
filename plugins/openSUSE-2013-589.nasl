#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-589.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75089);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-4520", "CVE-2013-0305", "CVE-2013-0306", "CVE-2013-1665");
  script_osvdb_id(86493, 90363, 90407, 90408);

  script_name(english:"openSUSE Security Update : python-django (openSUSE-SU-2013:1203-1)");
  script_summary(english:"Check for the openSUSE-2013-589 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"python-django was updated to 1.4.5 to fix various security issues and
bugs.

Update to 1.4.5 :

  - Security release.

  - Fix bnc#807175 / bnc#787521 / CVE-2012-4520 /
    CVE-2013-0305 / CVE-2013-0306 and CVE-2013-1665.

  - Update to 1.4.3 :

  - Security release :

  - Host header poisoning

  - Redirect poisoning

  - Please check release notes for details:
    https://www.djangoproject.com/weblog/2012/dec/10/securit
    y

  - Add a symlink from /usr/bin/django-admin.py to
    /usr/bin/django-admin

  - Update to 1.4.2 :

  - Security release :

  - Host header poisoning

  - Please check release notes for details:
    https://www.djangoproject.com/weblog/2012/oct/17/securit
    y

  - Update to 1.4.1 :

  - Security release :

  - Cross-site scripting in authentication views

  - Denial-of-service in image validation

  - Denial-of-service via get_image_dimensions()

  - Please check release notes for details:
    https://www.djangoproject.com/weblog/2012/jul/30/securit
    y-releases-issued

  - Add patch to support CSRF_COOKIE_HTTPONLY config"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2012/dec/10/security"
  );
  # https://www.djangoproject.com/weblog/2012/jul/30/security-releases-issued
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85c9c56c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2012/oct/17/security"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"python-django-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-django-1.4.5-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-django");
}
