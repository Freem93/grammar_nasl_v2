#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-309.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24769);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-1282", "CVE-2007-2867", "CVE-2007-2868");
  script_xref(name:"FEDORA", value:"2007-309");

  script_name(english:"Fedora Core 5 : thunderbird-1.5.0.10-1.fc5 (2007-309)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Mar 1 2007 Martin Stransky <stransky at redhat.com>
    1.5.0.10-1

    - Update to 1.5.0.10

    - Tue Dec 19 2006 Matthias Clasen <mclasen at
      redhat.com> 1.5.0.9-2

    - Add a Requires: launchmail (#219884)

    - Tue Dec 19 2006 Christopher Aillon <caillon at
      redhat.com> 1.5.0.9-1

    - Update to 1.5.0.9

    - Take firefox's pango fixes

    - Don't offer to import...nothing.

    - Tue Nov 7 2006 Christopher Aillon <caillon at
      redhat.com> 1.5.0.8-1

    - Update to 1.5.0.8

    - Allow choosing of download directory

    - Take the user to the correct directory from the
      Download Manager.

    - Patch to add support for printing via pango from
      Behdad.

    - Sun Oct 8 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.7-4

    - Default to use of system colors

    - Wed Oct 4 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.7-3

    - Bring the invisible character to parity with GTK+

    - Wed Sep 27 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.7-2

    - Fix crash when changing gtk key theme

    - Prevent UI freezes while changing GNOME theme

    - Remove verbiage about pango; no longer required by
      upstream.

    - Wed Sep 13 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.7-1

    - Update to 1.5.0.7

    - Thu Sep 7 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.5-8

    - Shuffle order of the install phase around

    - Thu Sep 7 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.5-7

    - Let there be art for Alt+Tab again

    - s/tbdir/mozappdir/g

    - Wed Sep 6 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.5-6

    - Fix for cursor position in editor widgets by tagoh and
      behdad (#198759)

    - Tue Sep 5 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.5-5

    - Update nopangoxft.patch

    - Fix rendering of MathML thanks to Behdad Esfahbod.

    - Update start page text to reflect the MathML fixes.

    - Enable pango by default on all locales

    - Build using -rpath

    - Re-enable GCC visibility

    - Thu Aug 3 2006 Kai Engert <kengert at redhat.com> -
      1.5.0.5-4

    - Fix a build failure in mailnews mime code.

    - Tue Aug 1 2006 Matthias Clasen <mclasen at redhat.com>
      - 1.5.0.5-3

    - Rebuild

    - Thu Jul 27 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.5-2

    - Update to 1.5.0.5

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 1.5.0.4-2.1

    - rebuild

    - Mon Jun 12 2006 Kai Engert <kengert at redhat.com> -
      1.5.0.4-2

    - Update to 1.5.0.4

    - Fix desktop-file-utils requires

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-March/001535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e20333a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC5", reference:"thunderbird-1.5.0.10-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"thunderbird-debuginfo-1.5.0.10-1.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
