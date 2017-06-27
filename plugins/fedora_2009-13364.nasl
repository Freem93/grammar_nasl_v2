#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-13364.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43338);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:41:46 $");

  script_bugtraq_id(37372);
  script_xref(name:"FEDORA", value:"2009-13364");

  script_name(english:"Fedora 11 : drupal-6.15-1.fc11 (2009-13364)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CORE-2009-009 * Project: Drupal
    core * Version: 5.x, 6.x * Date: 2009-December-16 *
    Security risk: Not critical * Exploitable from: Remote *
    Vulnerability: Cross site scripting -------- DESCRIPTION
    --------------------------------------------------------
    - Multiple vulnerabilities were discovered in Drupal.
    .... Contact category name cross-site scripting The
    Contact module does not correctly handle certain user
    input when displaying category information. Users
    privileged to create contact categories can insert
    arbitrary HTML and script code into the contact module
    administration page. Such a cross-site scripting attack
    may lead to the malicious user gaining administrative
    access. Wikipedia has more information about cross-site
    scripting [1] (XSS). This issue affects Drupal 6.x and
    Drupal 5.x. .... Menu description cross-site scripting
    The Menu module does not correctly handle certain user
    input when displaying the menu administration overview.
    Users privileged to create new menus can insert
    arbitrary HTML and script code into the menu module
    administration page. Such a cross-site scripting attack
    may lead to the malicious user gaining administrative
    access. Wikipedia has more information about cross-site
    scripting [2] (XSS). This issue affects Drupal 6.x only.
    -------- VERSIONS AFFECTED
    --------------------------------------------------- *
    Drupal 5.x before version 5.21. * Drupal 6.x before
    version 6.15. -------- SOLUTION
    --------------------------------------------------------
    ---- Install the latest version: * If you are running
    Drupal 6.x then upgrade to Drupal 6.15 [3]. * If you are
    running Drupal 5.x then upgrade to Drupal 5.21 [4]. If
    you are unable to upgrade immediately, you can apply a
    patch to secure your installation until you are able to
    do a proper upgrade. Theses patches fix the security
    vulnerability, but do not contain other fixes which were
    released in Drupal 5.21 or Drupal 6.15. * To patch
    Drupal 6.14 use SA- CORE-2009-009-6.14.patch [5]. * To
    patch Drupal 5.20 use SA- CORE-2009-009-5.20.patch [6].
    -------- REPORTED BY
    --------------------------------------------------------
    - The contact category XSS issue was independently
    reported by mr.baileys and Justin Klein Keane [7]. The
    menu description XSS issue was reported by mr.baileys
    [8]. -------- FIXED BY
    --------------------------------------------------------
    ---- The contact category XSS issue was fixed by Justin
    Klein Keane [9] and Dave Reid [10]. The menu description
    XSS issue was fixed by Gabor Hojtsy [11] and Heine
    Deelstra [12]. -------- CONTACT
    --------------------------------------------------------
    ----- The security team for Drupal can be reached at
    security at drupal.org or via the form at
    http://drupal.org/contact. [1]
    http://en.wikipedia.org/wiki/Cross-site_scripting [2]
    http://en.wikipedia.org/wiki/Cross-site_scripting [3]
    http://ftp.drupal.org/files/projects/drupal-6.15.tar.gz
    [4]
    http://ftp.drupal.org/files/projects/drupal-5.21.tar.gz
    [5]
    http://drupal.org/files/sa-core-2009-009/SA-CORE-2009-00
    9-6.14.patch [6]
    http://drupal.org/files/sa-core-2009-009/SA-CORE-2009-00
    9-5.20.patch [7] http://drupal.org/user/302225 [8]
    http://drupal.org/user/383424 [9]
    http://drupal.org/user/302225 [10]
    http://drupal.org/user/53892 [11]
    http://drupal.org/user/4166 [12]
    http://drupal.org/user/17943
    _______________________________________________
    Security-news mailing list Security-news at drupal.org
    http://lists.drupal.org/mailman/listinfo/security-news

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/files/sa-core-2009-009/SA-CORE-2009-009-5.20.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/files/sa-core-2009-009/SA-CORE-2009-009-6.14.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.drupal.org/files/projects/drupal-5.21.tar.gz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.drupal.org/files/projects/drupal-6.15.tar.gz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.drupal.org/mailman/listinfo/security-news"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95b4fcd1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/18");
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
if (rpm_check(release:"FC11", reference:"drupal-6.15-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal");
}
