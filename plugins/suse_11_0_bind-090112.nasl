#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update bind-426.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39921);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/05 21:24:24 $");

  script_cve_id("CVE-2009-0025");

  script_name(english:"openSUSE Security Update : bind (bind-426)");
  script_summary(english:"Check for the bind-426 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update improves the verification of return values of openssl
functions. Prior this update it was possible to spoof answers signed
with DSA and NSEC3DSA. (CVE-2009-0025)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=464462"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"bind-9.4.2-39.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"bind-chrootenv-9.4.2-39.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"bind-devel-9.4.2-39.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"bind-libs-9.4.2-39.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"bind-utils-9.4.2-39.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"bind-libs-32bit-9.4.2-39.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
