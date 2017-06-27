#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8750.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55499);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-0702");
  script_bugtraq_id(46182);
  script_xref(name:"FEDORA", value:"2011-8750");

  script_name(english:"Fedora 15 : feh-1.14.1-1.fc15 (2011-8750)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes since 0.10.1 :

  - Bug fixes * Make zoom_default key work properly with
    --geometry * Only create caption directory when actually
    writing out a caption.
    <http://github.com/derf/feh/issues/42> * read directory
    contents sorted by filename instead of 'randomly' (as
    returned by readdir) by default. Thanks talisein!
    <https://github.com/derf/feh/pull/20> * Show certain
    warnings in the image window as well as on the
    commandline <http://github.com/derf/feh/issues/43> *
    Change a patch for NETWM fullscreen support to only
    apply to fullscreen windows. This fixes the moving
    windows bug in fluxbox (since fluxbox doesn't report its
    window border width).
    <http://github.com/derf/feh/issues/22>
    <http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=570903
    > * Minor manpage fixes.
    <http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=625683
    > * Fix --auto-zoom / --zoom max/fill documentation, the
    'Auto-Zoom' menu option is now always checked when these
    options are used * Set _NET_WM_NAME and
    _NET_WM_ICON_NAME properties
    <http://github.com/derf/feh/issues/44> * The
    zoom_default key now works fine with --scale-down
    <http://github.com/derf/feh/issues/41> * Fix access of
    uninitialized memory / malloc/realloc clash in continued
    theme definition handling. Having a theme line with just
    one option/value pair used to produce undefined
    behaviour * Fix segfault upon unloadable images when
    image-related format specifiers (e.g. %h) are used in
    --title * Fix Imlib2 caching bug in reload (only worked
    after the second try) * Show correct image dimensions in
    for cached thumbnails * Fix zooming when --scale-down is
    used * Make in/out zoom use equal zoom ratio

  - Behavior changes/compatability * --menu-style is now
    deprecated * The --menu-bg option has been deprecated.
    It will be removed along with --menu-style by the end of
    2012. <http://github.com/derf/feh/issues/27> * Since the
    manual is way better structured and more detailed than
    the --help output, it now simply refers to the manual. *
    The 'A' key (toggle_aliasing) now actually changes the
    current window, and not just the default for new windows
    * Show images in current directory when invoked without
    file arguments * The --bg options are now
    Xinerama-aware. That is, they set the image in the
    respective mode (scale/fill/max/center) on each Xinerama
    screen. Use --no-xinerama to disable this. * Add --zoom
    fill as equivalent for --auto-zoom * Remove builtin http
    client (--builtin) * http images are now viewed using
    libcurl, not wget (thanks to talisein) This adds libcurl
    as dependency, and removes the wget recommendation *
    Allow commandline options to override those set in a
    theme * Remove support for FEH_OPTIONS (was deprecated
    >5 years ago) * Restrict available modifiers to
    Control/Mod1/Mod4 * The themes are now read from
    ~/.config/feh/themes (BC for .fehrc exists) * Key
    bindings can now be configured via ~/.config/feh/keys *
    Removes --rcpath, use XDG_CONFIG_HOME instead * Increase
    movement steps for Ctrl+Left etc.

  - Features * You can now use the next/prev/jump keys to
    navigate thumbnails. Use the render key to open the
    currently selected thumbnail.
    <http://github.com/derf/feh/issues/26> * Option to
    disable antialiasing, either global (--force-aliasing)
    or per image (press 'A' to toggle, keybinding
    toggle_aliasing) * Use SIGUSR1/SIGUSR2 to reload all
    images in multiwindow mode * Add --zoom max (zooming
    like in --bg-max)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=570903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=625683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/26"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/27"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/41"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/42"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/43"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://github.com/derf/feh/issues/44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=676389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/derf/feh/pull/20"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85a0dced"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected feh package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:feh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"feh-1.14.1-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "feh");
}
