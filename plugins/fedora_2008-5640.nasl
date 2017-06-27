#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-5640.
#

include("compat.inc");

if (description)
{
  script_id(33259);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_xref(name:"FEDORA", value:"2008-5640");

  script_name(english:"Fedora 8 : phpMyAdmin-2.11.7-1.fc8 (2008-5640)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update solves PMASA-2008-4 (phpMyAdmin security announcement)
from 2008-06-23: XSS on plausible insecure PHP installation; see
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-4 -
[interface] New field cannot be auto-increment and primary key - [dbi]
Incorrect interpretation for some mysqli field flags - [display] part
1: do not display a TEXT utf8_bin as BLOB (fixed for mysqli extension
only) - [interface] sanitize the after_field parameter, thanks to
Norman Hippert - [structure] do not remove the BINARY attribute in
drop-down - [session] Overriding session.hash_bits_per_character -
[interface] sanitize the table comments in table print view, thanks to
Norman Hippert - [general] Auto_Increment selected for TimeStamp by
Default - [display] No tilde for InnoDB row counter when we know it
for sure, thanks to Vladyslav Bakayev - dandy76 - [display] alt text
causes duplicated strings - [interface] Cannot upload BLOB into
existing row - [export] HTML in exports getting corrupted, thanks to
Jason Judge - jasonjudge - [interface] BINARY not treated as BLOB:
update/delete issues - [general] protection against XSS when
register_globals is on and .htaccess has no effect, thanks to Tim
Starling - [export] Firefox 3 and .sql.gz (corrupted); detect Gecko
1.9, thanks to Juergen Wind

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452497"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-June/011660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?859a502a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"phpMyAdmin-2.11.7-1.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
