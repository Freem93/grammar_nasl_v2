#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-10215.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47215);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:05:29 $");

  script_xref(name:"FEDORA", value:"2010-10215");

  script_name(english:"Fedora 13 : drupal-views-6.x.2.11-1.fc13 (2010-10215)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CONTRIB-2010-067
    (http://drupal.org/node/829840) * Project: Views
    (third-party module) * Version: 5.x, 6.x * Date:
    2010-June-16 * Security risk: Less critical *
    Exploitable from: Remote

  - Vulnerability: Multiple vulnerabilities --------
    DESCRIPTION
    --------------------------------------------------------
    - The Views module provides a flexible method for Drupal
    site designers to control how lists and tables of
    content are presented. -------- CROSS SITE REQUEST
    FORGERY (CSRF) ----------------------------------- The
    Views UI module, which is included with Views, can be
    used to enable/disable Views by following a link to a
    particular page (e.g.
    admin/build/views/disable/frontpage). As no protections,
    such as form tokens, are in place to prevent forged
    requests to these pages, the feature is vulnerable to a
    Cross Site Request Forgery (CSRF [1]) that would allow
    an attacker to enable/disable all Views on a site.
    Mitigating factors: If Views UI module is disabled Views
    will no longer be affected by this vulnerability. This
    issue affects Views for Drupal 5 and Drupal 6. --------
    CROSS SITE SCRIPTING (XSS)
    ------------------------------------------ Under certain
    circumstances, Views could display URLs or aggregator
    feed titles without escaping, resulting in a Cross Site
    Scripting (XSS [2]) vulnerability. An attacker could
    exploit this to gain full administrative access. This
    issue affects Views for Drupal 6 only. -------- VERSIONS
    AFFECTED
    --------------------------------------------------- *
    Views module for Drupal 5.x versions prior to 5.x-1.8 *
    Views module for Drupal 6.x versions prior to 6.x-2.11
    Drupal core is not affected. If you do not use the
    contributed Views [3] module, there is nothing you need
    to do. -------- SOLUTION
    --------------------------------------------------------
    ---- Install the latest version: * If you use the Views
    module for Drupal 5.x upgrade to Views 5.x-1.8 [4] * If
    you use the Views module for Drupal 6.x upgrade to Views
    6.x-2.11 [5] See also the Views project page [6].
    -------- REPORTED BY
    --------------------------------------------------------
    - * The Cross Site Request Forgery (CSRF) vulnerability
    was reported by Martin Barbella (mbarbella [7]). * The
    Cross Site Scripting (XSS) vulnerabilities were reported
    by Earl Miles (merlinofchaos [8]), module maintainer and
    Daniel Wehner (dereine [9]), module co-maintainer
    -------- FIXED BY
    --------------------------------------------------------
    ---- * Earl Miles (merlinofchaos [10]), module
    maintainer -------- CONTACT
    --------------------------------------------------------
    ----- The Drupal security team [11] can be reached at
    security at drupal.org or via the form at
    http://drupal.org/contact. * [1]
    http://en.wikipedia.org/wiki/Csrf * [2]
    http://en.wikipedia.org/wiki/Cross-site_scripting * [3]
    http://drupal.org/project/views * [4]
    http://drupal.org/node/829848 * [5]
    http://drupal.org/node/829846 * [6]
    http://drupal.org/project/views * [7]
    http://drupal.org/user/633600 * [8]
    http://drupal.org/user/26979 * [9]
    http://drupal.org/user/99340 * [10]
    http://drupal.org/user/26979 * [11]
    http://drupal.org/security-team

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/829840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/829846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/829848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/project/views"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Csrf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/043202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05e99613"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal-views package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal-views");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/21");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"drupal-views-6.x.2.11-1.fc13")) flag++;


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
