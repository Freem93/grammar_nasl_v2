#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-5002.
#

include("compat.inc");

if (description)
{
  script_id(38798);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:50:37 $");

  script_bugtraq_id(34946);
  script_xref(name:"FEDORA", value:"2009-5002");

  script_name(english:"Fedora 10 : drupal-6.12-1.fc10 (2009-5002)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes SA-CORE-2009-006 ( http://drupal.org/node/461886 ). Remember to
log in to your site as the admin user before upgrading this package.
After upgrading the package, browse to http://host/drupal/update.php
to run the upgrade script. When outputting user-supplied data Drupal
strips potentially dangerous HTML attributes and tags or escapes
characters which have a special meaning in HTML. This output filtering
secures the site against cross site scripting attacks via user input.
Certain byte sequences that are valid in the UTF-8 specification are
potentially dangerous when interpreted as UTF-7. Internet Explorer 6
and 7 may decode these characters as UTF-7 if they appear before the
<meta http-equiv ='Content-Type' /> tag that specifies the page
content as UTF-8, despite the fact that Drupal also sends a real HTTP
header specifying the content as UTF-8. This enables attackers to
execute cross site scripting attacks with UTF-7. SA- CORE-2009-005 -
Drupal core - Cross site scripting contained an incomplete fix for the
issue. HTML exports of books are still vulnerable, which means that
anyone with edit permissions for pages in outlines is able to insert
arbitrary HTML and script code in these exports. Additionally, the
taxonomy module allows users with the 'administer taxonomy' permission
to inject arbitrary HTML and script code in the help text of any
vocabulary. Wikipedia has more information about cross site scripting
(XSS).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/461886"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-May/023573.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2fd1ac2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/18");
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
if (rpm_check(release:"FC10", reference:"drupal-6.12-1.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal");
}
