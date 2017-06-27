#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-8162.
#

include("compat.inc");

if (description)
{
  script_id(40455);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:50:39 $");

  script_cve_id("CVE-2009-3156");
  script_bugtraq_id(35790);
  script_xref(name:"FEDORA", value:"2009-8162");

  script_name(english:"Fedora 10 : drupal-date-6.x.2.3-0.fc10 (2009-8162)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Advisory ID: DRUPAL-SA-CONTRIB-2009-046 * Project: Date
    (third-party module) * Version: 6.x * Date: 2009-July-29
    * Security risk: Moderately critical * Exploitable from:
    Remote * Vulnerability: Cross Site Scripting --------
    DESCRIPTION
    --------------------------------------------------------
    - The Date module provides a date CCK field that can be
    added to any content type. The Date Tools module that is
    bundled with Date module does not properly escape user
    input when displaying labels for fields on a content
    type. A malicious user with the 'use date tools'
    permission of the Date Tools sub- module, or the
    'administer content types' permission could attempt a
    cross site scripting [1] (XSS) attack when creating a
    new content type, leading to the user gaining full
    administrative access. -------- VERSIONS AFFECTED
    --------------------------------------------------- *
    Date for Drupal 6.x prior to 6.x-2.3 Drupal core is not
    affected. If you do not use the contributed Date module,
    there is nothing you need to do. -------- SOLUTION
    --------------------------------------------------------
    ---- Upgrade to the latest version: * If you use Date
    for Drupal 6.x upgrade to Date 6.x-2.3 [2] Note that the
    'use date tools' permission has been renamed as
    'administer date tools' to clarify that this is an
    administrative permission (it allows the creation of new
    content types via a wizard form). You will need to
    re-assign this permission to any roles that were using
    it. See also the Date project page [3]. --------
    REPORTED BY
    --------------------------------------------------------
    - Stella Power [4] of the Drupal Security Team --------
    FIXED BY
    --------------------------------------------------------
    ---- Stella Power [5] and Karen Stevenson [6], the
    project maintainer. -------- CONTACT
    --------------------------------------------------------
    ----- The security contact for Drupal can be reached at
    security at drupal.org or via the form at
    http://drupal.org/contact. [1]
    http://en.wikipedia.org/wiki/Cross-site_scripting [2]
    http://drupal.org/node/534332 [3]
    http://drupal.org/project/date [4]
    http://drupal.org/user/66894 [5]
    http://drupal.org/user/66894 [6]
    http://drupal.org/user/45874

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/534332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/project/date"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Cross-site_scripting"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/027241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31807578"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal-date package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal-date");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/01");
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
if (rpm_check(release:"FC10", reference:"drupal-date-6.x.2.3-0.fc10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal-date");
}
