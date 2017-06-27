#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update evolution-776.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40214);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:49:33 $");

  script_cve_id("CVE-2009-0582");

  script_name(english:"openSUSE Security Update : evolution (evolution-776)");
  script_summary(english:"Check for the evolution-776 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"camel's NTLM SASL authentication mechanism as used by evolution did
not properly validate server's challenge packets (CVE-2009-0582). 

This update also includes the following non-security fixes :

  - Fixes a critical crasher in mailer component. 

  - Fixes creation of recurrence monthly items in GroupWise. 

  - Includes fixes for some usability issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=419303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=475541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=477697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484213"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-mono-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-pilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtkhtml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtkhtml2-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
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

if ( rpm_check(release:"SUSE11.1", reference:"evolution-2.24.1.1-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-data-server-2.24.1.1-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-data-server-devel-2.24.1.1-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-data-server-lang-2.24.1.1-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-devel-2.24.1.1-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-lang-2.24.1.1-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-mono-providers-0.1.1-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"evolution-pilot-2.24.1.1-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"gtkhtml2-3.24.1.1-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"gtkhtml2-devel-3.24.1.1-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"gtkhtml2-lang-3.24.1.1-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"evolution-data-server-32bit-2.24.1.1-5.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution-data-server");
}
