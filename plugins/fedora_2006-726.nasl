#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-726.
#

include("compat.inc");

if (description)
{
  script_id(24132);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:27 $");

  script_xref(name:"FEDORA", value:"2006-726");

  script_name(english:"Fedora Core 5 : kdebase-3.5.3-0.3.fc5 (2006-726)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Jun 15 2006 Than Ngo <than at redhat.com>
    6:3.5.3-0.3.fc5

    - fix BR

    - Wed Jun 14 2006 Than Ngo <than at redhat.com>
      6:3.5.3-0.2.fc5

    - apply patch to to fix #194659, CVE-2006-2449 KDM
      symlink attack vulnerability thanks to KDE security
      team

  - Thu Jun 8 2006 Than Ngo <than at redhat.com>
    6:3.5.3-0.1.fc5

    - update to 3.5.3

    - Fri May 12 2006 Than Ngo <than at redhat.com>
      6:3.5.2-0.5.fc5

    - fix 190836, xmTextFieldClass widgets don't work
      properly

    - fix 186425, KDE Terminal Sessions applet does not
      display konsole bookmarks

    - fix 153202, startkde gets wrong field from
      space_tmp/space_home with finnish

    - fix 191049, KDE screensaver calls PAM incorrectly

    - fix 191306, Kde Help Center can't build an index

    - fix 192832, konsole crashes on kde logout

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-June/000295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f95ddfed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdebase, kdebase-debuginfo and / or kdebase-devel
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"kdebase-3.5.3-0.3.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kdebase-debuginfo-3.5.3-0.3.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kdebase-devel-3.5.3-0.3.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-debuginfo / kdebase-devel");
}
