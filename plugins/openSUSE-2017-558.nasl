#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-558.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100041);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2016-10220", "CVE-2016-9601", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-2017-558)");
  script_summary(english:"Check for the openSUSE-2017-558 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript fixes the following security
vulnerabilities :

CVE-2017-8291: A remote command execution and a -dSAFER bypass via a
crafted .eps document were exploited in the wild. (bsc#1036453)

CVE-2016-9601: An integer overflow in the bundled jbig2dec library
could have been misused to cause a Denial-of-Service. (bsc#1018128)

CVE-2016-10220: A NULL pointer dereference in the PDF Transparency
module allowed remote attackers to cause a Denial-of-Service.
(bsc#1032120)

CVE-2017-5951: A NULL pointer dereference allowed remote attackers to
cause a denial of service via a crafted PostScript document.
(bsc#1032114)

CVE-2017-7207: A NULL pointer dereference allowed remote attackers to
cause a denial of service via a crafted PostScript document.
(bsc#1030263)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
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

if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-debuginfo-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-debugsource-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-devel-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-debuginfo-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-debugsource-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-devel-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-x11-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-x11-debuginfo-9.15-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-debuginfo-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-debugsource-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-devel-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-mini-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-mini-debuginfo-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-mini-debugsource-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-mini-devel-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-x11-9.15-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ghostscript-x11-debuginfo-9.15-11.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}
