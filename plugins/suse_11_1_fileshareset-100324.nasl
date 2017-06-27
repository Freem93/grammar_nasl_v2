#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update fileshareset-2204.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45534);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 19:49:33 $");

  script_cve_id("CVE-2010-0436");

  script_name(english:"openSUSE Security Update : fileshareset (fileshareset-2204)");
  script_summary(english:"Check for the fileshareset-2204 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KDE KDM contains a local race condition which allows to make
arbitrary files world-writable. CVE-2010-0436 has been assigned to
this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584223"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fileshareset packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fileshareset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-nsplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-runtime-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:misc-console-font");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"fileshareset-2.0-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-beagle-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-devel-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-extra-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-kdm-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-nsplugin-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-runtime-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-samba-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdebase3-session-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"misc-console-font-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"kdebase3-32bit-3.5.10-17.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"kdebase3-runtime-32bit-3.5.10-17.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fileshareset / kdebase3 / kdebase3-32bit / kdebase3-beagle / etc");
}
