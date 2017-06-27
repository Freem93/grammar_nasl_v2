#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gvim-4822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31190);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:11:35 $");

  script_name(english:"openSUSE 10 Security Update : gvim (gvim-4822)");
  script_summary(english:"Check for the gvim-4822 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vim allows to open content via external programs if the argument
contains a 'http:' sub-string. It insecurely invoked external web
browsers to fetch the remote content."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gvim packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"gvim-6.4.6-19.12") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"vim-6.4.6-19.12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"gvim-7.0-40") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"vim-7.0-40") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"vim-enhanced-7.0-40") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"gvim-7.1-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"vim-7.1-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"vim-base-7.1-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"vim-data-7.1-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"vim-enhanced-7.1-44.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvim / vim / vim-enhanced / vim-base / vim-data");
}
