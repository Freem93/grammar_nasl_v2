#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-6317.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47429);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_osvdb_id(63591, 63592);
  script_xref(name:"FEDORA", value:"2010-6317");

  script_name(english:"Fedora 12 : drupal-views-6.x.2.9-1.fc12 (2010-6317)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SA-CONTRIB-2010-036 - Views - multiple vulnerabilities
------------------------------------------------------ * Advisory ID:
[DRUPAL-SA-CONTRIB-2010-036](http://drupal.org/node/765022) * Project:
Views (third-party module) * Version: 5.x, 6.x * Date: 2010-April-7 *
Security risk: Critical * Exploitable from: Remote * Vulnerability:
Cross Site Scripting (XSS), arbitrary code execution DESCRIPTION
----------- The Views module provides a flexible method for Drupal
site designers to control how lists of content are presented. Views
accepts parameters in the URL and uses them in an AJAX callback. The
values were not filtered, thus allowing injection of JavaScript code
via the AJAX response. A user tricked into visiting a crafted URL
could be exposed to arbitrary script or HTML injected into the page.
In addition, the Views module does not properly sanitize file
descriptions when displaying them in a view, thus the the file
desciptions may be used to inject arbitrary script or HTML. Such cross
site scripting [1] (XSS) attacks may lead to a malicious user gaining
full administrative access. These vulnerabilities affect only the
Drupal 6 version. The file description vulnerability is mitigated by
the fact that the attacker must have permission to upload files. In
both the Drupal 5 and Drupal 6 versions, users with permission to
'administer views' can execute arbitrary PHP code using the views
import feature. An additional check for the permission 'use PHP for
block visibility' has been added to insure that the site administrator
has already granted users of the import functionality the permission
to execute PHP. VERSIONS AFFECTED ----------------- * Versions of
Views for Drupal 6.x prior to 6.x-2.9 * Versions of Views for Drupal
5.x prior to 5.x-1.7 Note - the 6.x-3.x branch alpha releases are
affected also. If you do not use the contributed Views module, there
is nothing you need to do. SOLUTION -------- Install the latest
version: * If you use Views for Drupal 6.x upgrade to Views 6.x-2.9
[2] or any later version. * If you use Views for Drupal 6.x upgrade to
Views 5.x-1.7 [3] or any later version. Also see the Views [4] project
page. REPORTED BY ----------- * XSS via AJAX parameters reported by
Angel Lozano Alcazar of S21Sec * XSS via file descriptions reported by
Martin Barbella [5]

  - PHP execution reported by Derek Wright (dww [6]) of the
    Drupal Security Team [7] FIXED BY -------- * Earl Miles
    (merlinofchaos [8]) Views project maintainer. CONTACT
    ------- The security contact for Drupal can be reached
    at security at drupal.org or via the form at
    http://drupal.org/contact.

  - [1] http://en.wikipedia.org/wiki/Cross-site_scripting *
    [2] http://drupal.org/node/765088 * [3]
    http://drupal.org/node/765090 * [4]
    http://drupal.org/project/views * [5]
    http://drupal.org/user/633600 * [6]
    http://drupal.org/user/46549 * [7]
    http://drupal.org/security-team * [8]
    http://drupal.org/user/26979

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/765022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/765088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/765090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/project/views"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfeb81f7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal-views package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal-views");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"drupal-views-6.x.2.9-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal-views");
}
