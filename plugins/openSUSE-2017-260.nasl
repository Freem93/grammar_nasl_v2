#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-260.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97280);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2012-0876", "CVE-2012-6702", "CVE-2016-5300");

  script_name(english:"openSUSE Security Update : expat (openSUSE-2017-260)");
  script_summary(english:"Check for the openSUSE-2017-260 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for expat fixes the following security issues :

  - CVE-2012-6702: Expat, when used in a parser that has not
    called XML_SetHashSalt or passed it a seed of 0, made it
    easier for context-dependent attackers to defeat
    cryptographic protection mechanisms via vectors
    involving use of the srand function. (bsc#983215)

  - CVE-2016-5300: The XML parser in Expat did not use
    sufficient entropy for hash initialization, which
    allowed context-dependent attackers to cause a denial of
    service (CPU consumption) via crafted identifiers in an
    XML document. NOTE: this vulnerability exists because of
    an incomplete fix for CVE-2012-0876. (bsc#983216)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983216"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected expat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:expat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:expat-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:expat-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexpat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexpat-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexpat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexpat1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexpat1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexpat1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"expat-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"expat-debuginfo-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"expat-debugsource-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libexpat-devel-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libexpat1-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libexpat1-debuginfo-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"expat-debuginfo-32bit-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libexpat-devel-32bit-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libexpat1-32bit-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libexpat1-debuginfo-32bit-2.1.0-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"expat-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"expat-debuginfo-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"expat-debugsource-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexpat-devel-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexpat1-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libexpat1-debuginfo-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"expat-debuginfo-32bit-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexpat-devel-32bit-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexpat1-32bit-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libexpat1-debuginfo-32bit-2.1.0-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "expat / expat-debuginfo / expat-debuginfo-32bit / expat-debugsource / etc");
}
