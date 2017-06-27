#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-6049.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39399);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:50:38 $");

  script_bugtraq_id(35304);
  script_xref(name:"FEDORA", value:"2009-6049");

  script_name(english:"Fedora 11 : drupal-views-6.x.2.6-1.fc11 (2009-6049)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CONTRIB-2009-037 [0] * Project:
    Views * Versions: 6.x-2.x * Date: 2009-June-10 *
    Security risk: Moderately critical * Exploitable from:
    Remote * Vulnerability: Cross Site Scripting (XSS),
    Access Bypass -------- DESCRIPTION
    --------------------------------------------------------
    - The Views module provides a flexible method for Drupal
    site designers to control how lists of content are
    presented. In the Views UI administrative interface when
    configuring exposed filters, user input presented as
    possible exposed filters is not correctly filtered,
    potentially allowing malicious users to insert arbitrary
    HTML and script code into these pages. In addition,
    content entered by users with 'administer views'
    permission into the View name when defining custom views
    is subsequently displayed without being filtered. Such
    cross site scripting [1] (XSS) attacks may lead to a
    malicious user gaining full administrative access. An
    access bypass may exist where unpublished content owned
    by the anonymous user (e.g. content created by a user
    whose account was later deleted) is visible to any
    anonymous user there is a view already configured to
    show it incorrectly. An additional access bypass may
    occur because Views may generate queries which
    disrespect node access control. Users may be able to
    access private content if they have permission to see
    the resulting View. -------- VERSIONS AFFECTED
    --------------------------------------------------- *
    Versions of Views for Drupal 6.x prior to 6.x-2.6 Drupal
    core is not affected. If you do not use the Views
    module, there is nothing you need to do. --------
    SOLUTION
    --------------------------------------------------------
    ---- Install the latest version. * If you use Views for
    Drupal 6.x upgrade to 6.x-2.6 [2] In addition,
    preventing the node access bypass may require adding
    *node: access filters* to the View manually if using
    relationships to nodes that might be restricted. Also
    see the Views project page [3]. -------- REPORTED BY
    --------------------------------------------------------
    - * The exposed filters XSS was reported by Derek Wright
    (dww [4]) of the Drupal Security Team [5] * The XSS from
    the view name was reported by Justin Klein Keane
    (Justin_KleinKeane [6]) * The unpublished content access
    bypass was reported by Brandon Bergren (bdragon [7]) *
    The node access query bypass was reported by Moshe
    Weitzman (moshe weitzman [8]) of the Drupal Security
    Team [9] -------- FIXED BY
    --------------------------------------------------------
    ---- Earl Miles (merlinofchaos [10]) Views project
    maintainer. -------- CONTACT
    --------------------------------------------------------
    ----- The security contact for Drupal can be reached at
    security at drupal.org or via the form at
    http://drupal.org/contact and by selecting the security
    issues category. [0] http://drupal.org/node/488068 [1]
    http://en.wikipedia.org/wiki/Cross-site_scripting [2]
    http://drupal.org/node/488082 [3]
    http://drupal.org/project/views [4]
    http://drupal.org/user/46549 [5]
    http://drupal.org/security-team [6]
    http://drupal.org/user/302225 [7]
    http://drupal.org/user/53081 [8]
    http://drupal.org/user/23 [9]
    http://drupal.org/security-team [10]
    http://drupal.org/user/26979

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/488068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/488082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/project/views"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7483a5bc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal-views package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal-views");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/16");
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
if (rpm_check(release:"FC11", reference:"drupal-views-6.x.2.6-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal-views");
}
