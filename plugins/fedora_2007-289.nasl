#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-289.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24718);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_xref(name:"FEDORA", value:"2007-289");

  script_name(english:"Fedora Core 5 : devhelp-0.11-6.fc5 / epiphany-2.14.3-4.fc5 / seamonkey-1.0.8-0.5.1.fc5 / etc (2007-289)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora Core host is missing one or more security updates :

yelp-2.14.3-4.fc5 :

  - Fri Feb 16 2007 Martin Stransky <stransky at redhat.com>
    - 2.14.3-4

    - Rebuild against SeaMonkey

    - Fri Dec 22 2006 Martin Stransky <stransky at
      redhat.com> - 2.14.3-3

    - Rebuild against SeaMonkey

    - Tue Nov 14 2006 Martin Stransky <stransky at
      redhat.com> - 2.14.3-2

    - Rebuild against SeaMonkey

    - Wed Aug 2 2006 Matthias Clasen <mclasen at redhat.com>
      - 2.14.3-1.fc5

    - Update to 2.14.3

    - Mon May 29 2006 Matthias Clasen <mclasen at
      redhat.com> - 2.14.2-1

    - Update to 2.14.2

epiphany-2.14.3-4.fc5 :

  - Fri Feb 16 2007 Martin Stransky <stransky at redhat.com>
    - 2.14.3-4

    - Rebuild against SeaMonkey

    - Fri Dec 22 2006 Martin Stransky <stransky at
      redhat.com> - 2.14.3-3

    - Rebuild against SeaMonkey

    - Mon Nov 13 2006 Martin Stransky <stransky at
      redhat.com> - 2.14.3-2

    - Rebuild against SeaMonkey

    - Wed Aug 2 2006 Matthias Clasen <mclasen at redhat.com>
      - 2.14.3-1.fc5

    - Update to 2.14.3

    - Mon May 29 2006 Matthias Clasen <mclasen at
      redhat.com> - 2.14.2.1-1.fc5.1

    - Update to 2.14.2.1

    - Sun May 28 2006 Matthias Clasen <mclasen at
      redhat.com> - 2.14.2-1.fc5.1

    - Update to 2.14.2

devhelp-0.11-6.fc5 :

  - Fri Feb 16 2007 Martin Stransky <stransky at redhat.com>
    - 0.11-6

    - Rebuild against SeaMonkey

    - Fri Dec 22 2006 Martin Stransky <stransky at
      redhat.com> - 0.11-5

    - Rebuild against SeaMonkey

    - Mon Nov 13 2006 Martin Stransky <stransky at
      redhat.com> - 0.11-4

    - Rebuild against SeaMonkey

seamonkey-1.0.8-0.5.1.fc5 :

  - Thu Feb 15 2007 Martin Stransky <stransky at redhat.com>
    1.0.8-0.5.1

    - Update to 1.0.8

    - Thu Jan 18 2007 Martin Stransky <stransky at
      redhat.com> 1.0.7-0.6.0.1

    - created a link in /usr/bin/seamonkey

    - fixed mozilla-rebuild-databases.pl script, was called
      in %post with an incorrect path

  - fixed mozilla-config script

    - added a configuration from former extras SeaMonkey
      (#223848)

    - Thu Jan 4 2007 Martin Stransky <stransky at
      redhat.com> 1.0.7-0.6

    - Release bump

    - Thu Dec 21 2006 Martin Stransky <stransky at
      redhat.com> 1.0.7-0.1

    - Update to 1.0.7

    - Tue Dec 19 2006 Martin Stransky <stransky at
      redhat.com> 1.0.6-0.3

    - added dependencies on nspr-devel,nss-devel to
      seamonkey-devel package

    - Thu Dec 14 2006 Martin Stransky <stransky at
      redhat.com> 1.0.6-0.2.fc6

    - added ppc64 to arches

    - Fri Nov 10 2006 Martin Stransky <stransky at
      redhat.com> 1.0.6-0.1.fc6

    - moved to core

    - replaced nspr/nss with packages from core

    - Sun Nov 5 2006 Christopher Aillon <caillon at
      redhat.com> 1.0.6-0.1.el4

    - Update to 1.0.6 (RC)

    - Mon Sep 11 2006 Christopher Aillon <caillon at
      redhat.com> 1.0.5-0.1.el4

    - Update to 1.0.5

    - Wed Jul 26 2006 Christopher Aillon <caillon at
      redhat.com> 1.0.3-0.el4.1

    - Update to 1.0.3

    - Wed Jun 28 2006 Warren Togami <wtogami at redhat.com>
      1.0.2-0.1.0.EL4

    - Prevent obsolete script from replacing
      mozilla-xremote-client (#192639)

    - 1.0.2 security fixes

    - remove unused patches

    - Mon May 22 2006 Christopher Aillon <caillon at
      redhat.com> 1.0.1-0.1.3.EL4

    - Fix the -devel packages and pkg-config files

    - Fri May 19 2006 Christopher Aillon <caillon at
      redhat.com> 1.0.1-0.1.2.EL4

    - Import some fixes from the RHEL3 package

    - Fri May 12 2006 Christopher Aillon <caillon at
      redhat.com> 1.0.1-0.1.1.EL4

    - Initial SeaMonkey RPM

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ff7aeb4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe856ffd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76303a12"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f67cada"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/27");
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
if (rpm_check(release:"FC5", reference:"devhelp-0.11-6.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"devhelp-debuginfo-0.11-6.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"devhelp-devel-0.11-6.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"epiphany-2.14.3-4.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"epiphany-debuginfo-2.14.3-4.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"epiphany-devel-2.14.3-4.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-chat-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-debuginfo-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-devel-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-dom-inspector-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-js-debugger-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"seamonkey-mail-1.0.8-0.5.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"yelp-2.14.3-4.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"yelp-debuginfo-2.14.3-4.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-debuginfo / devhelp-devel / epiphany / etc");
}
