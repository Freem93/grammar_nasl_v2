#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update qt-3050.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27411);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:36:48 $");

  script_cve_id("CVE-2007-0242");

  script_name(english:"openSUSE 10 Security Update : qt (qt-3050)");
  script_summary(english:"Check for the qt-3050 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qt wrongly accepts overly long UTF-8 sequences due to a bug in the
UTF-8 decoder. This may lead to security problems unter certain
circumstances. The bug for example allows for script tag injection in
konqueror (CVE-2007-0242)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"qt-4.1.0-29.11") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"qt-devel-4.1.0-29.11") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"qt-32bit-4.1.0-29.11") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt / qt-32bit / qt-devel");
}