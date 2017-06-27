#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-16990.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57328);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:56:30 $");

  script_cve_id("CVE-2011-4088");
  script_xref(name:"FEDORA", value:"2011-16990");

  script_name(english:"Fedora 16 : abrt-2.0.7-2.fc16 / libreport-2.0.8-3.fc16 (2011-16990)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

libreport-2.0.8-3.fc16 :

  - Fri Dec 9 2011 Jiri Moskovcak <jmoskovc at redhat.com>
    2.0.8-3

    - fixed few crashes in bodhi plugin

    - Thu Dec 8 2011 Jiri Moskovcak <jmoskovc at redhat.com>
      2.0.8-2

    - fixed crash in bodhi plugin

    - re-upload better backtrace if available

    - fixed dupe finding for selinux

    - don't duplicate comments in bugzilla

    - fixed problem with empty release

    - Tue Dec 6 2011 Jiri Moskovcak <jmoskovc at redhat.com>
      2.0.8-1

    - new version

    - added bodhi plugin rhbz#655783

    - one tab per file on details page rhbz#751833

    - search box search thru all data (should help with
      privacy) rhbz#748457

    - fixed close button position rhbz#741230

    - rise the attachment limit to 4kb rhbz#712602

    - fixed make check (rpath problem)

    - save chnages in editable lines rhbz#710100

    - ignore backup files rhbz#707959

    - added support for proxies rhbz#533652

    - Resolves: 753183 748457 737991 723219 712602 711986
      692274 636000 631856 655783 741257 748457 741230
      712602 753183 748457 741230 712602 710100 707959
      533652

    - Sat Nov 5 2011 Jiri Moskovcak <jmoskovc at redhat.com>
      2.0.7-2

    - bumped release

    - Fri Nov 4 2011 Jiri Moskovcak <jmoskovc at redhat.com>
      2.0.7-1

    - new version

    - added support for bodhi (preview)

    - dropped unused patches

    - reporter-bugzilla/rhts: add code to prevent duplicate
      reporting. Closes rhbz#727494 (dvlasenk at redhat.com)

    - wizard: search thru all items + tabbed details
      rhbz#748457 (jmoskovc at redhat.com)

    - wizard: add 'I don't know what caused this problem'
      checkbox. Closes rhbz#712508 (dvlasenk at redhat.com)

    - reporter-bugzilla: add optional 'Product' parameter.
      Closes rhbz#665210 (dvlasenk at redhat.com)

    - rhbz#728190 - man pages contain suspicious version
      string (npajkovs at redhat.com)

    - reporter-print: expand leading ~/ if present. Closes
      rhbz#737991 (dvlasenk at redhat.com)

    - reporter-rhtsupport: ask rs/problems endpoint before
      creating new case. (working on rhbz#677052) (dvlasenk
      at redhat.com)

    - reporter-mailx: use Bugzilla's output format. Closes
      rhbz#717321. (dvlasenk at redhat.com)

    - report-newt: add option to display version
      (rhbz#741590) (mlichvar at redhat.com)

    - Resolves: #727494 #748457 #712508 #665210 rhbz#728190
      #737991 #677052 #717321 #741590

abrt-2.0.7-2.fc16 :

  - Thu Dec 8 2011 Jiri Moskovcak <jmoskovc at redhat.com>
    2.0.7-2

    - added man page

    - fixed weird number formatting

    - Wed Dec 7 2011 Jiri Moskovcak <jmoskovc at redhat.com>
      2.0.7-1

    - new version

    - disabled kerneloops.org

    - abrt-ccpp hook fixes

    - catch indentation errors in python rhbz#578969

    - fixed make check

    - fixed retrace-client to work with rawhide

    - require abrtd service in other services rhbz#752014

    - fixed problems with dupes rhbz#701717

    - keep abrt services enabled when updating F15->F16

    - Resolves: 752014 749891 749603 744887 730422 665210
      639068 625445 701717 752014 578969 732876 757683
      753183 756146 749100

    - Fri Nov 4 2011 Jiri Moskovcak <jmoskovc at redhat.com>
      2.0.6-1

    - new version

    - Resolves: #701171 #712508 #726033 #728194 #728314
      #730107 #733389 #738602

    - Resolves: #741242 #749365 #700252 #734298 #736016
      #738324 #748457 #692274

    - Resolves: #711986 #723219 #749891 #712602 #744887
      #749603 #625445 #665210

    - Resolves: #737991 #639068 #578969 #636000 #631856

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=749854"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5f77b2d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e1ca5f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected abrt and / or libreport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libreport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"abrt-2.0.7-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"libreport-2.0.8-3.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / libreport");
}
