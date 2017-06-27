#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1014.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93092);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-2059", "CVE-2015-8948", "CVE-2016-6261", "CVE-2016-6262", "CVE-2016-6263");

  script_name(english:"openSUSE Security Update : libidn (openSUSE-2016-1014)");
  script_summary(english:"Check for the openSUSE-2016-1014 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libidn fixes the following issues :

  - CVE-2016-6262 and CVE-2015-8948: Out-of-bounds-read when
    reading one zero byte as input (bsc#990189)

  - CVE-2016-6261: Out-of-bounds stack read in
    idna_to_ascii_4i (bsc#990190) 

  - CVE-2016-6263: stringprep_utf8_nfkc_normalize reject
    invalid UTF-8 (bsc#990191)

  - CVE-2015-2059: out-of-bounds read with stringprep on
    invalid UTF-8 (bsc#923241) 

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990191"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libidn packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/24");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libidn-debugsource-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libidn-devel-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libidn-tools-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libidn-tools-debuginfo-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libidn11-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libidn11-debuginfo-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libidn11-32bit-1.28-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libidn11-debuginfo-32bit-1.28-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libidn-debugsource / libidn-devel / libidn-tools / etc");
}