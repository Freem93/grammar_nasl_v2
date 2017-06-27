#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libfreebl3-5398.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75896);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-3640");
  script_osvdb_id(76858);

  script_name(english:"openSUSE Security Update : libfreebl3 (openSUSE-SU-2011:1241-1)");
  script_summary(english:"Check for the libfreebl3-5398 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mozilla update fixes the following security issues :

  - explicitely distrust DigiCert Sdn. Bhd (bnc#728520,
    bmo#698753)

  - make sure NSS_NoDB_Init does not try to use wrong
    certificate databases (CVE-2011-3640, bnc#726096,
    bmo#641052)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libfreebl3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
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

if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-debuginfo-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-debuginfo-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-debuginfo-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debuginfo-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debugsource-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-devel-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-debuginfo-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-debuginfo-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.12.11-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.12.11-1.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreebl3 / libfreebl3-32bit / libsoftokn3 / libsoftokn3-32bit / etc");
}
