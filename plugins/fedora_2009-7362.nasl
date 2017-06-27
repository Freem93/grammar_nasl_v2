#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-7362.
#

include("compat.inc");

if (description)
{
  script_id(39609);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:50:38 $");

  script_bugtraq_id(35548);
  script_xref(name:"FEDORA", value:"2009-7362");

  script_name(english:"Fedora 9 : drupal-6.13-1.fc9 (2009-7362)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes SA-CORE-2009-007 ( http://drupal.org/node/507572 ). Remember to
log in to your site as the admin user before upgrading this package.
After upgrading the package, browse to http://host/drupal/update.php
to run the upgrade script. Multiple vulnerabilities and weaknesses
were discovered in Drupal. Cross-site scripting The Forum module does
not correctly handle certain arguments obtained from the URL. By
enticing a suitably privileged user to visit a specially crafted URL,
a malicious user is able to insert arbitrary HTML and script code into
forum pages. Such a cross-site scripting attack may lead to the
malicious user gaining administrative access. Wikipedia has more
information about cross-site scripting (XSS). This issue affects
Drupal 6.x only. Input format access bypass User signatures have no
separate input format, they use the format of the comment with which
they are displayed. A user will no longer be able to edit a comment
when an administrator changes the comment's input format to a format
that is not accessible to the user. However they will still be able to
modify their signature, which will then be processed by the new input
format. If the new format is very permissive, via their signature, the
user may be able to insert arbitrary HTML and script code into pages
or, when the PHP filter is enabled for the new format, execute PHP
code. This issue affects Drupal 6.x only. Password leaked in URL When
an anonymous user fails to login due to mistyping his username or
password, and the page he is on contains a sortable table, the
(incorrect) username and password are included in links on the table.
If the user visits these links the password may then be leaked to
external sites via the HTTP referer. In addition, if the anonymous
user is enticed to visit the site via a specially crafted URL while
the Drupal page cache is enabled, a malicious user might be able to
retrieve the (incorrect) username and password from the page cache.
This issue affects both Drupal 5.x and Drupal 6.x

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/507572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500707"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026095.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1622fb0e"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/06");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"drupal-6.13-1.fc9")) flag++;


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
