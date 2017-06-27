#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-168.
#

include("compat.inc");

if (description)
{
  script_id(13722);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/21 21:09:31 $");

  script_xref(name:"FEDORA", value:"2004-168");

  script_name(english:"Fedora Core 2 : mailman-2.1.5-7 (2004-168)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes security issue CVE-2004-0412 noted in bug
https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=123559 Mailman
subscriber passwords could be retrieved by a remote attacker. Security
hole is fixed in mailman-2.1.5 Important Installation Note: Some users
have reported problems with bad queue counts after upgrading to
version 2.1.5, the operating assumption is this was caused by
performing an install while mailman was running. Prior to installing
this rpm stop the mailman service via: % /sbin/service mailman stop
Then after installation completes restart the service via: %
/sbin/service mailman start Red Hat RPM versions of mailman 2.1.5-6
and above have enhanced the init.d script that controls the mailman
service so that '/sbin/service mailman status' now returns valid
information. The RPM has been augmented to detect if mailman is
running prior to installation and if so it will temporarily stop
mailman during the install and restart mailman after the install
completes. If mailman was not running the RPM will not start mailman
after installation. Since the RPM depends on service status working
the installed version of mailman you are replacing must be at least
2.1.5-6 for the automatic pausing of mailman during installation to
work. This also means since this is the first RPM with this feature
you will need to manually pause mailman during installation, future
upgrades should be automatic.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=123559"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-July/000204.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43ecddeb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman and / or mailman-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"mailman-2.1.5-7")) flag++;
if (rpm_check(release:"FC2", reference:"mailman-debuginfo-2.1.5-7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo");
}
