#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ModemManager-564.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40167);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 19:55:04 $");

  script_cve_id("CVE-2009-0365", "CVE-2009-0578");

  script_name(english:"openSUSE Security Update : ModemManager (ModemManager-564)");
  script_summary(english:"Check for the ModemManager-564 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The NetworkManager configuration was too permissive and allowed any
user to read secrets (CVE-2009-0365) or manipulate the configuration
of other users (CVE-2009-0578)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478080"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ModemManager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ModemManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"ModemManager-0.1_20081203-6.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"NetworkManager-0.7.0.r4359-15.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"NetworkManager-devel-0.7.0.r4359-15.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"NetworkManager-glib-0.7.0.r4359-15.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ModemManager / NetworkManager / NetworkManager-devel / etc");
}
