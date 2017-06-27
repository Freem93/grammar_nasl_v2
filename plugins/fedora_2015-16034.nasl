#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-16034.
#

include("compat.inc");

if (description)
{
  script_id(86172);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:57:27 $");

  script_xref(name:"FEDORA", value:"2015-16034");

  script_name(english:"Fedora 22 : php-ZendFramework2-2.4.8-1.fc22 (2015-16034)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Zend Framework 2.4.8** **Security Update** * **ZF2015-07**: The
filesystem storage adapter of Zend\Cache was creating directories with
a liberal umask that could lead to local arbitrary code execution
and/or local privilege escalation. This release contains a patch that
ensures the directories are created using permissions of 0775 and
files using 0664 (essentially umask 0002). **Bug fixed** from upstream
[Changelog](http://framework.zend.com/changelog/2.4.8) * validate
against DateTimeImmutable instead of DateTimeInterface * treat 0.0 as
non-empty, restoring pre-2.4 behavior * deprecate 'magic' logic for
auto- attaching NonEmpty validators in favor of explicit attachment *
ensure fallback values work as per pre-2.4 behavior * update the
InputFilterInterface::add() docblock to match implementations * Fix
how missing optoinal fields are validated to match pre 2.4.0 behavior
* deprecate AllowEmpty and ContinueIfEmpty annotations, per
zend-inputfilter#26 * fix typos in aria attribute names of
AbstractHelper * fixes the ContentType header to properly handle
encoded parameter values * fixes the Sender header to allow mailbox
addresses without TLDs * fixes parsing of messages that contain an
initial blank line before headers * fixes the SetCookie header to
allow multiline values (as they are always encoded * fixes
DefaultRenderingStrategy errors due to controllers returning non-view
model results

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://framework.zend.com/changelog/2.4.8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-September/167698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bea612c5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-ZendFramework2 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ZendFramework2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC22", reference:"php-ZendFramework2-2.4.8-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-ZendFramework2");
}
