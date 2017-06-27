#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-10200.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47214);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:05:29 $");

  script_cve_id("CVE-2010-2352", "CVE-2010-2353");
  script_xref(name:"FEDORA", value:"2010-10200");

  script_name(english:"Fedora 13 : drupal-cck-6.x.2.7-1.fc13 (2010-10200)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CONTRIB-2010-065
    (http://drupal.org/node/829566) * Project: Content
    Construction Kit (CCK) (third-party module) * Version:
    5.x, 6.x * Date: 2010-June-16 * Security risk: Less
    Critical * Exploitable from: Remote * Vulnerability:
    Access Bypass -------- DESCRIPTION
    --------------------------------------------------------
    - The Content Construction Kit (CCK) project is a set of
    modules that allows you to add custom fields to nodes
    using a web browser. The CCK 'Node Reference' module can
    be configured to display referenced nodes as hidden,
    title, teaser or full view. Node access was not checked
    when displaying these which could expose view access on
    controlled nodes to unprivileged users. In addition,
    Node Reference provides a backend URL that is used for
    asynchronous requests by the 'autocomplete' widget to
    locate nodes the user can reference. This was not
    checking that the user had field level access to the
    source field, allowing direct queries to the backend URL
    to return node titles and IDs which the user would
    otherwise be unable to access. Note that as Drupal 5 CCK
    does not have any field access control functionality,
    this issue only applies to the Drupal 6 version.
    -------- VERSIONS AFFECTED
    --------------------------------------------------- *
    Content Construction Kit (CCK) module for Drupal 5.x
    versions prior to 5.x-1.11 * Content Construction Kit
    (CCK) module for Drupal 6.x versions prior to 6.x-2.7
    Drupal core is not affected. If you do not use the
    contributed Content Construction Kit (CCK) [1] module,
    together with any node or field access module there is
    nothing you need to do. -------- SOLUTION
    --------------------------------------------------------
    ---- Install the latest version: * If you use the
    Content Construction Kit (CCK) module for Drupal 5.x
    upgrade to Content Construction Kit (CCK) 5.x-1.11 [2] *
    If you use the Content Construction Kit (CCK) module for
    Drupal 6.x upgrade to Content Construction Kit (CCK)
    6.x-2.7 [3] See also the Content Construction Kit (CCK)
    project page [4]. -------- REPORTED BY
    --------------------------------------------------------
    - * recrit [5] * Marc Ferran (markus_petrux) [6], module
    co-maintainer -------- FIXED BY
    --------------------------------------------------------
    ---- * Yves Chedemois (yched) [7], module co-maintainer
    * Marc Ferran (markus_petrux) [8], module co-maintainer
    * Karen Stevenson (KarenS) [9], module co- maintainer
    -------- CONTACT
    --------------------------------------------------------
    ----- The Drupal security team [10] can be reached at
    security at drupal.org or via the form at
    http://drupal.org/contact. * [1]
    http://drupal.org/project/cck * [2]
    http://drupal.org/node/828986 * [3]
    http://drupal.org/node/828988 * [4]
    http://drupal.org/project/cck * [5]
    http://drupal.org/user/452914 * [6]
    http://drupal.org/user/39593 * [7]
    http://drupal.org/user/39567 * [8]
    http://drupal.org/user/39593 * [9]
    http://drupal.org/user/45874 * [10]
    http://drupal.org/security-team

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/828986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/828988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/829566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/project/cck"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/043191.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c73b51b6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal-cck package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal-cck");
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
if (rpm_check(release:"FC13", reference:"drupal-cck-6.x.2.7-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal-cck");
}
