#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-219.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81763);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/30 13:52:21 $");

  script_cve_id("CVE-2014-3619");

  script_name(english:"openSUSE Security Update : glusterfs (openSUSE-2015-219)");
  script_summary(english:"Check for the openSUSE-2015-219 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glusterfs was updated to fix a fragment header infinite loop denial of
service attack (CVE-2014-3619)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919879"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glusterfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfrpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfrpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfxdr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfxdr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglusterfs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglusterfs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"glusterfs-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glusterfs-debuginfo-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glusterfs-debugsource-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glusterfs-devel-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgfapi0-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgfapi0-debuginfo-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgfrpc0-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgfrpc0-debuginfo-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgfxdr0-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgfxdr0-debuginfo-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libglusterfs0-3.4.0~qa9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libglusterfs0-debuginfo-3.4.0~qa9-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-debuginfo / glusterfs-debugsource / etc");
}
