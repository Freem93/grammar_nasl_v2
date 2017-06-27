#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update finch-1625.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(43054);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-3025", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3084", "CVE-2009-3085", "CVE-2009-3615");

  script_name(english:"openSUSE Security Update : finch (finch-1625)");
  script_summary(english:"Check for the finch-1625 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of pidgin fixes the following issues :

  - CVE-2009-3026: CVSS v2 Base Score: 5.0 Allowed to send
    confidential data unencrypted even if SSL was chosen by
    user.

  - CVE-2009-3025: CVSS v2 Base Score: 4.3 Remote denial of
    service in yahoo IM plug-in.

  - CVE-2009-3083: CVSS v2 Base Score: 5.0 Remote denial of
    service in MSN plug-in.

  - CVE-2009-3084: CVSS v2 Base Score: 5.0 Remote denial of
    service in MSN plug-in.

  - CVE-2009-3085: CVSS v2 Base Score: 5.0 Remote denial of
    service in XMPP plug-in.

  - CVE-2009-3615: CVSS v2 Base Score: 5.0 Remote denial of
    service in ICQ plug-in.

  - QQ protocol upgrade Migrate all QQ accounts to QQ2008."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=536602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548072"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected finch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20, 119, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cdparanoia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:check-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:desktop-file-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fam-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-vfs2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-vfs2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstreamer-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstreamer-0_10-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libogg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libogg0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liboil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liboil-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtheora0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtheora0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisual-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvorbis-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"cdparanoia-3.10.2-3.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"check-0.9.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"desktop-file-utils-0.15-86.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"fam-2.7.0-133.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"finch-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"finch-devel-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gnome-vfs2-2.24.1-3.4") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gnome-vfs2-lang-2.24.1-3.4") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gstreamer-0_10-0.10.24-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gstreamer-0_10-lang-0.10.24-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libgstreamer-0_10-0-0.10.24-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libogg0-1.1.4-2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"liboil-0.3.16-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-devel-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-lang-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-meanwhile-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-mono-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpurple-tcl-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libtheora0-1.0.0-2.5") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libvisual-0.4.0-177.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libvorbis-1.2.0-83.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pidgin-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pidgin-devel-2.6.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pidgin-otr-3.2.0-142.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"check-32bit-0.9.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"fam-32bit-2.7.0-133.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"gnome-vfs2-32bit-2.24.1-3.4") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"gstreamer-0_10-32bit-0.10.24-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libgstreamer-0_10-0-32bit-0.10.24-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libogg0-32bit-1.1.4-2.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"liboil-32bit-0.3.16-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libtheora0-32bit-1.0.0-2.5") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libvisual-32bit-0.4.0-177.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libvorbis-32bit-1.2.0-83.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cdparanoia / check / check-32bit / desktop-file-utils / fam / etc");
}
