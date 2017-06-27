#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9754.
#

include("compat.inc");

if (description)
{
  script_id(41020);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:57:46 $");

  script_bugtraq_id(36428);
  script_xref(name:"FEDORA", value:"2009-9754");

  script_name(english:"Fedora 10 : drupal-date-6.x.2.4-0.fc10 (2009-9754)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CONTRIB-2009-057 (
    http://drupal.org/node/579144 )

    - Project: Date (third-party module) * Version: 5.x, 6.x
      * Date: 2009-September-16 * Security risk: Moderately
      critical * Exploitable from: Remote * Vulnerability:
      Cross Site Scripting -------- DESCRIPTION
      ------------------------------------------------------
      --- The Date module provides a date CCK field that can
      be added to any content type. The Date module does not
      properly escape user data correctly in some cases when
      setting the page title. A malicious user with
      permission to post date content could attempt a cross
      site scripting [1] (XSS) attack when creating or
      editing content, leading to the user gaining full
      administrative access. -------- VERSIONS AFFECTED
      --------------------------------------------------- *
      Date for Drupal 6.x prior to 6.x-2.4 * Date for Drupal
      6.x prior to 5.x-2.8 Drupal core is not affected. If
      you do not use the contributed Date module, there is
      nothing you need to do. -------- SOLUTION
      ------------------------------------------------------
      ------ Upgrade to the latest version: * If you use
      Date for Drupal 6.x upgrade to Date 6.x-2.4 [2]

  - If you use Date for Drupal 5.x upgrade to Date 5.x-2.8
    [3] See also the Date project page [4]. --------
    REPORTED BY
    --------------------------------------------------------
    - The Acquia, Inc. support team -------- FIXED BY
    --------------------------------------------------------
    ---- Karen Stevenson [5], the project maintainer.
    -------- CONTACT
    --------------------------------------------------------
    ----- The security contact for Drupal can be reached at
    security at drupal.org or via the form at
    http://drupal.org/contact. [1]
    http://en.wikipedia.org/wiki/Cross-site_scripting [2]
    http://drupal.org/node/579000 [3]
    http://drupal.org/node/578998 [4]
    http://drupal.org/project/date [5]
    http://drupal.org/user/45874

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/578998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/579000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/579144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/project/date"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6786c71f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal-date package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal-date");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/21");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"drupal-date-6.x.2.4-0.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal-date");
}
