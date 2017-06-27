#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1117.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93703);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2013-7447");

  script_name(english:"openSUSE Security Update : gtk2 (openSUSE-2016-1117)");
  script_summary(english:"Check for the openSUSE-2016-1117 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This gtk2 update to version 2.24.31 fixes the following issues :

Security issues fixed :

  - CVE-2013-7447: Fixed integer overflow in image handling
    (boo#966682).

Bugs fixed :

  - Changes from version 2.24.31 :

  + Backport many file chooser entry fixes and cleanups.

  + Don't crash if invisible files are deleted.

  + Bugs fixed: bgo#555087, bgo#586367, bgo#635287,
    bgo#640698, bgo#648419, bgo#672271, bgo#679333,
    bgo#687196, bgo#703220 (CVE-2013-7447), bgo#720330,
    bgo#729927, bgo#737777, bgo#752707, bgo#756450,
    bgo#765120, bgo#765193, bgo#768163, bgo#764996,
    bgo#769126.

  - Changes from version 2.24.30 :

  + Win32: Build fixes.

  + X11: Support Randr 1.5 monitor information.

  + Bugs fixed: bgo#722815, bgo#612611, bgo#699652,
    bgo#698652, bgo#758893.

  + Updated translations.

  - Changes from version 2.24.29 :

  + OS X: Partial aspect ratio support.

  + Bugs fixed: bgo#345345, bgo#745127, bgo#749507,
    bgo#752638, bgo#753644, bgo#753691, bgo#753992,
    bgo#754046.

  + Updated translations.

GTK2 Engine and branding packages were rebuilt to match the updated
gtk2 package (boo#999375)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999375"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gtk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-clearlooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-clearlooks-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-clearlooks-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-clearlooks-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-crux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-crux-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-crux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-crux-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-glide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-glide-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-glide-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-glide-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-hcengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-hcengine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-industrial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-industrial-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-industrial-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-industrial-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-mist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-mist-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-mist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-mist-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-redmond95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-redmond95-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-redmond95-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-redmond95-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-thinice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-thinice-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-thinice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-thinice-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engines-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engines-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-amharic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-amharic-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-amharic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-amharic-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-inuktitut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-inuktitut-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-inuktitut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-inuktitut-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-multipress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-multipress-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-multipress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-multipress-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-thai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-thai-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-thai-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-thai-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-vietnamese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-vietnamese-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-vietnamese-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-vietnamese-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-xim-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-xim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodule-xim-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodules-tigrigna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodules-tigrigna-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodules-tigrigna-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-immodules-tigrigna-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-theme-clearlooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-theme-crux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-theme-industrial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-theme-mist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-theme-redmond95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-theme-thinice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-tools-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-tools-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Gtk-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"gtk2-branding-SLED-13.2-14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-branding-openSUSE-13.2-14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-branding-upstream-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-data-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-debugsource-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-devel-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-devel-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-clearlooks-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-clearlooks-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-crux-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-crux-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-glide-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-glide-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-hcengine-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-hcengine-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-industrial-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-industrial-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-mist-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-mist-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-redmond95-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-redmond95-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-thinice-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engine-thinice-debuginfo-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engines-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engines-debugsource-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-engines-devel-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-amharic-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-amharic-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-inuktitut-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-inuktitut-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-multipress-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-multipress-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-thai-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-thai-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-vietnamese-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-vietnamese-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-xim-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodule-xim-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodules-tigrigna-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-immodules-tigrigna-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-lang-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-theme-clearlooks-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-theme-crux-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-theme-industrial-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-theme-mist-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-theme-redmond95-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-theme-thinice-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-tools-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gtk2-tools-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgtk-2_0-0-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgtk-2_0-0-debuginfo-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-Gtk-2_0-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-devel-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-devel-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-clearlooks-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-clearlooks-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-crux-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-crux-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-glide-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-glide-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-industrial-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-industrial-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-mist-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-mist-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-redmond95-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-redmond95-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-thinice-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-engine-thinice-debuginfo-32bit-2.20.2-18.14.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-amharic-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-amharic-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-inuktitut-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-inuktitut-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-multipress-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-multipress-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-thai-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-thai-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-vietnamese-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-vietnamese-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-xim-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodule-xim-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodules-tigrigna-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-immodules-tigrigna-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-tools-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gtk2-tools-debuginfo-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgtk-2_0-0-32bit-2.24.31-4.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgtk-2_0-0-debuginfo-32bit-2.24.31-4.17.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk2-branding-SLED / gtk2-branding-openSUSE / etc");
}
