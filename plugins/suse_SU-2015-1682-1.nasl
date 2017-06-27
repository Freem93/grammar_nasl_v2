#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1682-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86308);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/05 21:32:29 $");

  script_cve_id("CVE-2015-5234", "CVE-2015-5235");
  script_osvdb_id(127019, 127031);

  script_name(english:"SUSE SLED12 Security Update : icedtea-web (SUSE-SU-2015:1682-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Java IcedTea-Web Plugin was updated to 1.6.1 bringing various
features, bug- and securityfixes.

  - Enabled Entry-Point attribute check

  - permissions sandbox and signed app and unsigned app with
    permissions all-permissions now run in sandbox instead
    of not t all.

  - fixed DownloadService

  - comments in deployment.properties now should persists
    load/save

  - fixed bug in caching of files with query

  - fixed issues with recreating of existing shortcut

  - trustAll/trustNone now processed correctly

  - headless no longer shows dialogues

  - RH1231441 Unable to read the text of the buttons of the
    security dialogue

  - Fixed RH1233697 icedtea-web: applet origin spoofing
    (CVE-2015-5235, bsc#944208)

  - Fixed RH1233667 icedtea-web: unexpected permanent
    authorization of unsigned applets (CVE-2015-5234,
    bsc#944209)

  - MissingALACAdialog made available also for unsigned
    applications (but ignoring actual manifest value) and
    fixed

  - NetX

  - fixed issues with -html shortcuts

  - fixed issue with -html receiving garbage in width and
    height

  - PolicyEditor

  - file flag made to work when used standalone

  - file flag and main argument cannot be used in
    combination

The update to 1.6 is included and brings :

  - Massively improved offline abilities. Added Xoffline
    switch to force work without inet connection.

  - Improved to be able to run with any JDK

  - JDK 6 and older no longer supported

  - JDK 8 support added (URLPermission granted if
    applicable)

  - JDK 9 supported

  - Added support for Entry-Point manifest attribute

  - Added KEY_ENABLE_MANIFEST_ATTRIBUTES_CHECK deployment
    property to control scan of Manifest file

  - starting arguments now accept also -- abbreviations

  - Added new documentation

  - Added support for menu shortcuts - both javaws
    applications/applets and html applets are supported

  - added support for -html switch for javaws. Now you can
    run most of the applets without browser at all

  - Control Panel

  - PR1856: ControlPanel UI improvement for lower
    resolutions (800*600)

  - NetX

  - PR1858: Java Console accepts multi-byte encodings

  - PR1859: Java Console UI improvement for lower
    resolutions (800*600)

  - RH1091563: [abrt] icedtea-web-1.5-2.fc20: Uncaught
    exception java.lang.ClassCastException in method
    sun.applet.PluginAppletViewer$8.run()

  - Dropped support for long unmaintained -basedir argument

  - Returned support for -jnlp argument

  - RH1095311, PR574 - References class sun.misc.Ref removed
    in OpenJDK 9

  - fixed, and so buildable on JDK9

  - Plugin

  - PR1743 - Intermittant deadlock in PluginRequestProcessor

  - PR1298 - LiveConnect - problem setting array elements
    (applet variables) from JS

  - RH1121549: coverity defects

  - Resolves method overloading correctly with superclass
    heirarchy distance

  - PolicyEditor

  - codebases can be renamed in-place, copied, and pasted

  - codebase URLs can be copied to system clipboard

  - displays a progress dialog while opening or saving files

  - codebases without permissions assigned save to file
    anyway (and re-appear on next open)

  - PR1776: NullPointer on save-and-exit

  - PR1850: duplicate codebases when launching from security
    dialogs

  - Fixed bug where clicking 'Cancel' on the 'Save before
    Exiting' dialog could result in the editor exiting
    without saving changes

  - Keyboard accelerators and mnemonics greatly improved

  - 'File - New' allows editing a new policy without first
    selecting the file to save to

  - Common

  - PR1769: support signed applets which specify Sandbox
    permissions in their manifests

  - Temporary Permissions in security dialog now
    multi-selectable and based on PolicyEditor permissions

The update to 1.5.2 brings OpenJDK 8 support (fate#318956)

  - NetX

  - RH1095311, PR574 - References class sun.misc.Ref removed
    in OpenJDK 9

  - fixed, and so buildable on JDK9

  - RH1154177 - decoded file needed from cache

  - fixed NPE in https dialog

  - empty codebase behaves as '.'

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5235.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151682-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a60ef531"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-642=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-642=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-plugin-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-plugin-1.6.1-2.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-plugin-debuginfo-1.6.1-2.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-plugin-debugsource-1.6.1-2.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web");
}
