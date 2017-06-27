#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-671.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91439);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-8872", "CVE-2016-4804");

  script_name(english:"openSUSE Security Update : dosfstools (openSUSE-2016-671)");
  script_summary(english:"Check for the openSUSE-2016-671 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dosfstools fixes the following issues :

  - fixed buffer overflows based on insufficient size of
    variable for storing FAT size (CVE-2016-4804,
    boo#980377)

  - dosfstools-3.0.26-read-fat-overflow.patch

  - fixed memory corruption when setting FAT12 entries
    (CVE-2015-8872, boo#980364)

  - dosfstools-3.0.26-off-by-2.patch

  - Fix attempt to rename root dir in fsck due to
    uninitialized fields [boo#912607]

  - Drop gpg-offline build-time requirement; this is now
    handled by the local source validator"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980377"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dosfstools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dosfstools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dosfstools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dosfstools-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/02");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"dosfstools-3.0.26-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dosfstools-debuginfo-3.0.26-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dosfstools-debugsource-3.0.26-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dosfstools-3.0.26-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dosfstools-debuginfo-3.0.26-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dosfstools-debugsource-3.0.26-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dosfstools / dosfstools-debuginfo / dosfstools-debugsource");
}
