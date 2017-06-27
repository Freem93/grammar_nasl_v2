#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-542.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85371);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/13 13:44:24 $");

  script_cve_id("CVE-2015-3622");

  script_name(english:"openSUSE Security Update : gnutls (openSUSE-2015-542)");
  script_summary(english:"Check for the openSUSE-2015-542 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - fix for CVE-2015-3622 in bundled libtasn1 (bsc#929414)

  - invalid read in octet string

  - added gnutls-CVE-2015-3622.patch

  - fix for GNUTLS-SA-2015-2 (bsc#929690)

  - ServerKeyExchange signature issue

  - added gnutls-GNUTLS-SA-2015-2.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929690"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-openssl27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-openssl27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"gnutls-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnutls-debuginfo-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnutls-debugsource-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutls-devel-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutls-openssl-devel-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutls-openssl27-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutls-openssl27-debuginfo-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutls28-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutls28-debuginfo-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutlsxx-devel-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutlsxx28-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgnutlsxx28-debuginfo-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgnutls28-32bit-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgnutls28-debuginfo-32bit-3.2.4-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gnutls-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gnutls-debuginfo-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gnutls-debugsource-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutls-devel-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutls-openssl-devel-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutls-openssl27-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutls-openssl27-debuginfo-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutls28-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutls28-debuginfo-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutlsxx-devel-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutlsxx28-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgnutlsxx28-debuginfo-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgnutls28-32bit-3.2.18-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgnutls28-debuginfo-32bit-3.2.18-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-debugsource / libgnutls-devel / etc");
}
