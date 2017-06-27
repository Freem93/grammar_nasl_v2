#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-431d39fbff.
#

include("compat.inc");

if (description)
{
  script_id(89223);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_xref(name:"FEDORA", value:"2015-431d39fbff");

  script_name(english:"Fedora 22 : roundcubemail-1.1.4-2.fc22 (2015-431d39fbff)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Release 1.1.4** - Add workaround for
https://bugs.php.net/bug.php?id=70757 (#1490582) - Fix duplicate
messages in list and wrong count after delete (#1490572) - Fix so
Installer requires PHP5 - Make brute-force attacks harder by
re-generating security token on every failed login (#1490549) - Slow
down brute- force attacks by waiting for a second after failed login
(#1490549) - Fix .htaccess rewrite rules to not block .well-known URIs
(#1490615) - Fix mail view scaling on iOS (#1490551) - Fix so
database_attachments::cleanup() does not remove attachments from other
sessions (#1490542) - Fix responses list update issue after response
name change (#1490555) - Fix bug where message preview was
unintentionally reset on check-recent action (#1490563) - Fix bug
where HTML messages with invalid/excessive css styles couldn't be
displayed (#1490539) - Fix redundant blank lines when using HTML and
top posting (#1490576) - Fix redundant blank lines on start of text
after html to text conversion (#1490577)

  - Fix HTML sanitizer to skip <!-- node type X --> in
    output (#1490583) - Fix invalid LDAP query in ACL user
    autocompletion (#1490591) - Fix regression in displaying
    contents of message/rfc822 parts (#1490606) - Fix
    handling of message/rfc822 attachments on replies and
    forwards (#1490607) - Fix PDF support detection in
    Firefox > 19 (#1490610) - Fix path traversal
    vulnerability (CWE-22) in setting a skin (#1490620) -
    Fix so drag-n-drop of text (e.g. recipient addresses) on
    compose page actually works (#1490619) **Packaging
    changes:** * add .log suffix to all log file names, and
    rotate them all (may requires to switch back to provided
    logrotate configuration)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.php.net/bug.php?id=70757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1269155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1269164"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ff7422a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"roundcubemail-1.1.4-2.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
