#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update bind-2529.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27167);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:06:05 $");

  script_name(english:"openSUSE 10 Security Update : bind (bind-2529)");
  script_summary(english:"Check for the bind-2529 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security problem was fixed in the ISC BIND nameserver version 9.3.4,
these are addressed by this security update.

If recursion is enabled, a remote attacker can dereference a freed
fetch context causing the daemon to abort / crash."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/25");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"bind-9.3.2-17.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"bind-libs-9.3.2-17.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"bind-utils-9.3.2-17.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"bind-libs-32bit-9.3.2-17.15") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"bind-9.3.2-56.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"bind-libs-9.3.2-56.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"bind-utils-9.3.2-56.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"bind-libs-32bit-9.3.2-56.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
