#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-912.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75217);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1881");
  script_bugtraq_id(62714);

  script_name(english:"openSUSE Security Update : librsvg (openSUSE-SU-2013:1786-1)");
  script_summary(english:"Check for the openSUSE-2013-912 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"librsvg was updated to fix a denial a XML External Entity Inclusion
problem, where files on the system could be imported into the SVG.
(CVE-2013-1881)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00114.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840753"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected librsvg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-svg-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-svg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-engine-svg-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-amharic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-amharic-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-amharic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-amharic-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-inuktitut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-inuktitut-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-inuktitut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-inuktitut-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-multipress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-multipress-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-multipress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-multipress-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-thai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-thai-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-thai-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-thai-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-vietnamese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-vietnamese-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-vietnamese-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-vietnamese-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-xim-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-xim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodule-xim-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodules-tigrigna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodules-tigrigna-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodules-tigrigna-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-immodules-tigrigna-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-tools-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-tools-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-3-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgtk-3-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Gtk-3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Rsvg-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"gdk-pixbuf-loader-rsvg-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk2-engine-svg-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk2-engine-svg-debuginfo-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-branding-upstream-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-data-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-debugsource-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-devel-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-devel-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-amharic-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-amharic-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-inuktitut-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-inuktitut-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-multipress-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-multipress-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-thai-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-thai-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-vietnamese-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-vietnamese-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-xim-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodule-xim-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodules-tigrigna-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-immodules-tigrigna-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-lang-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-tools-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gtk3-tools-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgtk-3-0-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgtk-3-0-debuginfo-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"librsvg-2-2-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"librsvg-2-2-debuginfo-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"librsvg-debugsource-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"librsvg-devel-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rsvg-view-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rsvg-view-debuginfo-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-Gtk-3_0-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-Rsvg-2_0-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-debuginfo-32bit-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk2-engine-svg-32bit-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk2-engine-svg-debuginfo-32bit-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-amharic-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-amharic-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-inuktitut-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-inuktitut-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-multipress-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-multipress-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-thai-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-thai-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-vietnamese-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-vietnamese-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-xim-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodule-xim-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodules-tigrigna-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-immodules-tigrigna-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-tools-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"gtk3-tools-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgtk-3-0-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgtk-3-0-debuginfo-32bit-3.4.4-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-32bit-2.36.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gdk-pixbuf-loader-rsvg-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk2-engine-svg-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk2-engine-svg-debuginfo-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-branding-upstream-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-data-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-debugsource-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-devel-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-devel-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-amharic-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-amharic-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-inuktitut-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-inuktitut-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-multipress-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-multipress-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-thai-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-thai-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-vietnamese-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-vietnamese-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-xim-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodule-xim-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodules-tigrigna-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-immodules-tigrigna-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-lang-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-tools-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gtk3-tools-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgtk-3-0-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgtk-3-0-debuginfo-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"librsvg-2-2-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"librsvg-2-2-debuginfo-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"librsvg-debugsource-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"librsvg-devel-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rsvg-view-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rsvg-view-debuginfo-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-Gtk-3_0-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-Rsvg-2_0-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-debuginfo-32bit-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk2-engine-svg-32bit-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk2-engine-svg-debuginfo-32bit-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-devel-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-devel-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-amharic-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-amharic-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-inuktitut-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-inuktitut-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-multipress-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-multipress-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-thai-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-thai-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-vietnamese-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-vietnamese-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-xim-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodule-xim-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodules-tigrigna-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-immodules-tigrigna-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-tools-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"gtk3-tools-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgtk-3-0-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgtk-3-0-debuginfo-32bit-3.6.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.36.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-32bit-2.36.4-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "librsvg");
}
