#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-531.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99926);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/02 13:34:10 $");

  script_cve_id("CVE-2017-7875");

  script_name(english:"openSUSE Security Update : feh (openSUSE-2017-531)");
  script_summary(english:"Check for the openSUSE-2017-531 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for feh on Leap 42.1 fixes this security issue :

  - CVE-2017-7875: In wallpaper.c in feh if a malicious
    client pretended to be the E17 window manager, it was
    possible to trigger an out-of-boundary heap write while
    receiving an IPC message. An integer overflow leads to a
    buffer overflow and/or a double free (bsc#1034567).

This update for feh on Leap 42.2 to version 2.18.3 fixes several
issues.

This security issue was fixed on Leap 42.2 :

  - CVE-2017-7875: In wallpaper.c in feh if a malicious
    client pretended to be the E17 window manager, it was
    possible to trigger an out-of-boundary heap write while
    receiving an IPC message. An integer overflow leads to a
    buffer overflow and/or a double free (bsc#1034567).

These non-security issue was fixed on Leap 42.2 :

  - boo#955576: added jpegexiforient

  - Fixed image-specific format specifiers not being updated
    correctly in thumbnail mode window titles

  - Fixed memory leak when closing images opened from
    thumbnail mode

  - Fixed a possible out of bounds read caused by an
    unterminated string when using --output to save images
    in long paths

  - Fixed out of bounds read/write when handling empty or
    broken caption files.

  - Fixed memory leak when saving a filelist or image whose
    target filename already exists.

  - Fixed image-specific format specifiers not being updated
    correctly

  - New key binding: ! - zoom_fill (zoom to fill window, may
    cut off image parts

  - Disable EXIF-based auto rotation by default

  - Added --auto-rotate option to enable auto rotation 

  - Added feh-makefile_app.patch -- fix install location of
    icons

  - Install feh icon (both 48x48 and scalable SVG) to
    /usr/share/icons when running 'make install app=1'

  - Fixed --sort not being respected after the first reload
    when used in conjunction with --reload

  - All key actions can now also be bound to a button by
    specifying them in .config/feh/buttons. However, note
    that button actions can not be bound to keys.

  - Rename 'menu' key action to 'toggle_menu', 'prev' to
    'prev_img' and 'next' to 'next_img'. The old names are
    still supported, but no longer documented.

  - feh now also sets the X11 _NET_WM_PID and
    WM_CLIENT_MACHINE window properties

  - Fixed compilation on systems where HOST_NAME_MAX is not
    defined

  - Also support in-place editing for images loaded via
    libcurl or imagemagick. Results will not be written back
    to disk in this case.

  - Fixed crash when trying to rotate a JPEG image without
    having jpegtran / jpegexiforient installed

  - Handle failing fork() calls gracefully

  - Fixed invalid key/button definitions mis-assigning
    keys/buttons to other actions

  - Added sort mode --sort dirname to sort images by
    directory instead of by name.

  - Added navigation keys next_dir (]) and prev_dir ([) to
    jump to the first image of the nex/previous directory 

  - Fixed toggle_filenames key displaying wrong file numbers
    in multiwindow mode

  - Rescale image when resizing a window and --scale-down or
    --geometry is active.

  - Fixed --keep-zoom-vp not keeping the viewport x/y
    offsets 

  - Fixed w (size_to_image) key not updating window size
    when --scale-down or --geometry is active

  - Added --insecure option to disable HTTPS certificate
    checks

  - Added --no-recursive option to disable recursive
    directory expansion.

  - Improve --scale-down in tiling environments.

  - --action and --action[1..9] now support action titles

  - -f / --filelist: Do not print useless error message when
    a correct filelist file is specified

  - -f / --filelist: Fix bug in '-' / '/dev/stdin' handling
    affecting feh running in ksh and possibly other
    environments

  - Add --xinerama-index option for background setting

  - When removing the last image in slidsehow mode, stay on
    the last (previously second-to-last) image

  - Allow --sort and --randomize to override each other
    (most recently specified option wins) instead of always
    preferring --sort

  - Thumbnail mode: Mark image as processed when executing
    an action (--action) by clicking on an image

  - It is now possible to override feh's idea of the active
    xinerama screen using the --xinerama-index option

  - Removed (undocumented) feature allowing to override
    feh's idea of the active xinerama screen by setting the
    XINERAMA_SCREEN environment variable

  - Removed obsolete gpg macro"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955576"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected feh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:feh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:feh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:feh-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"feh-2.13.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"feh-debuginfo-2.13.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"feh-debugsource-2.13.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"feh-2.18.3-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"feh-debuginfo-2.18.3-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"feh-debugsource-2.18.3-6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "feh / feh-debuginfo / feh-debugsource");
}
