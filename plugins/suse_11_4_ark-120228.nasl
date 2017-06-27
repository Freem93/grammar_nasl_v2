#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ark-5902.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75792);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:32 $");

  script_cve_id("CVE-2011-2725");
  script_osvdb_id(74180);

  script_name(english:"openSUSE Security Update : ark (openSUSE-SU-2012:0322-1)");
  script_summary(english:"Check for the ark-5902 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ark was prone to a path traversal vulnerability allowing a
maliciously-crafted zip file to allow for an arbitrary file to be
displayed and, if the user has appropriate credentials, removed
(CVE-2011-2725)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708268"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ark packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:filelight");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:filelight-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcalc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcharselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kcharselect-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-printer-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdeutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdeutils4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kfloppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kfloppy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kgpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kgpg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kremotecontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kremotecontrol-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktimer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktimer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwalletmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwalletmanager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwikdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwikdisk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:superkaramba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:superkaramba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sweeper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sweeper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ark-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ark-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"filelight-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"filelight-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kcalc-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kcalc-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kcharselect-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kcharselect-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kde4-printer-applet-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kdeutils4-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kdeutils4-debugsource-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kdf-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kdf-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kfloppy-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kfloppy-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kgpg-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kgpg-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kremotecontrol-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kremotecontrol-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ktimer-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ktimer-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kwalletmanager-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kwalletmanager-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kwikdisk-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kwikdisk-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"superkaramba-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"superkaramba-debuginfo-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"sweeper-4.6.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"sweeper-debuginfo-4.6.0-4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ark");
}
