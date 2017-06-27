#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-789.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87006);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/23 14:38:53 $");

  script_cve_id("CVE-2015-6031");

  script_name(english:"openSUSE Security Update : miniupnpc (openSUSE-2015-789)");
  script_summary(english:"Check for the openSUSE-2015-789 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MiniUPnP was updated to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-6031: XML parser buffer overflow (boo#950759)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950759"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected miniupnpc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc10-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:miniupnpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:miniupnpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-miniupnpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-miniupnpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/23");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libminiupnpc-devel-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libminiupnpc10-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libminiupnpc10-debuginfo-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"miniupnpc-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"miniupnpc-debuginfo-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-miniupnpc-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-miniupnpc-debuginfo-1.9-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libminiupnpc-devel-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libminiupnpc10-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libminiupnpc10-debuginfo-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"miniupnpc-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"miniupnpc-debuginfo-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-miniupnpc-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-miniupnpc-debuginfo-1.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libminiupnpc-devel-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libminiupnpc10-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libminiupnpc10-debuginfo-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"miniupnpc-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"miniupnpc-debuginfo-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-miniupnpc-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-miniupnpc-debuginfo-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libminiupnpc10-32bit-1.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libminiupnpc10-debuginfo-32bit-1.9-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libminiupnpc-devel / libminiupnpc10 / libminiupnpc10-debuginfo / etc");
}
