#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-428.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75001);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/10 14:11:56 $");

  script_cve_id("CVE-2013-1619");
  script_osvdb_id(89848);

  script_name(english:"openSUSE Security Update : gnutls (openSUSE-SU-2013:0807-1)");
  script_summary(english:"Check for the openSUSE-2013-428 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in gnutls :

  - Fix bug[ bnc#802651] CVE-2013-1619( gnutls): Luck-13
    issue Add patch file: CVE-2013-1619.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802651"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-extra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-extra28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-extra28-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"gnutls-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gnutls-debuginfo-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gnutls-debugsource-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-devel-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-extra-devel-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-extra28-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-extra28-debuginfo-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-openssl-devel-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-openssl27-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls-openssl27-debuginfo-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls28-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutls28-debuginfo-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutlsxx-devel-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutlsxx28-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgnutlsxx28-debuginfo-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgnutls28-32bit-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgnutls28-debuginfo-32bit-3.0.3-5.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnutls-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnutls-debuginfo-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnutls-debugsource-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutls-devel-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutls-openssl-devel-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutls-openssl27-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutls-openssl27-debuginfo-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutls28-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutls28-debuginfo-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutlsxx-devel-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutlsxx28-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgnutlsxx28-debuginfo-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgnutls28-32bit-3.0.20-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgnutls28-debuginfo-32bit-3.0.20-1.4.1") ) flag++;

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