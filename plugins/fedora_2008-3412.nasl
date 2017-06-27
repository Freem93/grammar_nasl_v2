#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3412.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(32106);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:13:39 $");

  script_cve_id("CVE-2008-1670");
  script_xref(name:"FEDORA", value:"2008-3412");

  script_name(english:"Fedora 8 : kde-filesystem-4-14.fc8 / kdebase-runtime-4.0.3-10.fc8.1 / kdebase4-4.0.3-9.fc8 / etc (2008-3412)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

kdepimlibs-4.0.3-3.fc8 :

  - Thu Apr 3 2008 Kevin Kofler <Kevin at tigcc.ticalc.org>
    4.0.3-3

    - rebuild (again) for the fixed %{_kde4_buildtype}

    - Mon Mar 31 2008 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4.0.3-2

    - rebuild for NDEBUG and _kde4_libexecdir

    - Fri Mar 28 2008 Than Ngo <than at redhat.com> 4.0.3-1

    - 4.0.3

    - -apidocs: Drop Requires: %name

    - include noarch build hooks (not enabled)

    - Thu Mar 6 2008 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4.0.2-2

    - build apidocs and put them into an -apidocs subpackage
      (can be turned off)

    - BR doxygen, graphviz and qt4-doc when building apidocs

    - Thu Feb 28 2008 Than Ngo <than at redhat.com> 4.0.2-1

    - 4.0.2

    - Wed Jan 30 2008 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4.0.1-2

    - don't delete kconf_update script, it has been fixed to
      do the right thing

    - Wed Jan 30 2008 Rex Dieter <rdieter at
      fedoraproject.org> 4.0.1-1

    - 4.0.1

    - Mon Jan 7 2008 Than Ngo <than at redhat.com> 4.0.0-1

    - 4.0.0

    - Tue Dec 11 2007 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 3.97.0-2

    - rebuild for changed _kde4_includedir

    - Wed Dec 5 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 3.97.0-1

    - kde-3.97.0

    - Thu Nov 29 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 3.96.2-1

    - kde-3.96.2

    - Tue Nov 27 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 3.96.1-2

    - kde-3.96.1

    - Thu Nov 15 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 3.96.0-1

    - kde-3.96.0

    - Fri Nov 9 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 3.95.2-1

    - kde-3.95.2

    - Mon Nov 5 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 3.95.0-1

    - kde-3.95.0 (kde4 dev platform rc1)

kdebase-runtime-4.0.3-10.fc8.1 / kdebase4-4.0.3-9.fc8 /
kdelibs4-4.0.3-7.fc8 / qt4-4.3.4-11.fc8 :

  - Bug #443766 - CVE-2008-1670 kdelibs: Buffer overflow in
    KHTML's image loader

kde-filesystem-4-14.fc8 :

  - Thu Apr 3 2008 Kevin Kofler <Kevin at tigcc.ticalc.org>
    4-14

    - don't define %{_kde4_debug} in macros.kde4 anymore

    - Wed Apr 2 2008 Rex Dieter <rdieter at
      fedoraproject.org> 4-13

    - define %{_kde4_buildtype} in macros.kde4 too

    - Mon Mar 31 2008 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4-12

    - actually define %{_kde4_libexecdir} in macros.kde4

    - Mon Mar 31 2008 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4-11

    - add %{_kde4_libexecdir}, set LIBEXEC_INSTALL_DIR to it

    - don't own %{_kde4_libdir} which is just %{_libdir}

    - Mon Mar 31 2008 Rex Dieter <rdieter at
      fedoraproject.org> 4-10

    - macros.kde4: _kde4_buildtype=FEDORA

    - Fri Mar 28 2008 Than Ngo <than at redhat.com> 4-9

    - internal services shouldn't be displayed in menu,
      bz#321771

    - Sun Jan 27 2008 Rex Dieter <rdieter at
      fedoraproject.org> 4-8

    - should not own %_datadir/desktop-directories/
      (#430420)

    - Fri Jan 25 2008 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4-7

    - own %{_kde4_appsdir}/color-schemes

    - Mon Jan 7 2008 Rex Dieter
      <rdieter[AT]fedoraproject.org> 4-6

    - -Requires: redhat-rpm-config (revert 4-1 addition)

    - Sun Dec 30 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 4-5

    - +%_datadir/autostart, %_kde4_datadir/autostart

    - Tue Dec 11 2007 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4-4

    - set INCLUDE_INSTALL_DIR in %cmake_kde4

    - Tue Dec 11 2007 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4-3

    - actually create the directory listed in the file list

    - Tue Dec 11 2007 Kevin Kofler <Kevin at
      tigcc.ticalc.org> 4-2

    - set kde4_includedir to %_kde4_prefix/include/kde4

    - Mon Nov 19 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 4-1

    - Version: 4

    - %cmake_kde4: add -DCMAKE_SKIP_RPATH:BOOL=ON

    - Requires: redhat-rpm-config (for proper rpm macro
      defs) (hmm... may need a new -devel pkg somewhere)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443766"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96121af5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009640.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a70b721a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f308eff4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63df3f3e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f4e8594"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7fe4e57"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/01");
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
if (rpm_check(release:"FC8", reference:"kde-filesystem-4-14.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kdebase-runtime-4.0.3-10.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"kdebase4-4.0.3-9.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kdelibs4-4.0.3-7.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kdepimlibs-4.0.3-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"qt4-4.3.4-11.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-filesystem / kdebase-runtime / kdebase4 / kdelibs4 / kdepimlibs / etc");
}
