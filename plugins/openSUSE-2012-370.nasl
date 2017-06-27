#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-370.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74672);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2012-2737");
  script_osvdb_id(83398);

  script_name(english:"openSUSE Security Update : accountsservice (openSUSE-SU-2012:0845-1)");
  script_summary(english:"Check for the openSUSE-2012-370 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of accountservice fixed a flaw in
user_change_icon_file_authorized_cb() that could be exploited by local
attackers to read arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768807"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected accountsservice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:accountsservice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:accountsservice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:accountsservice-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaccountsservice0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaccountsservice0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"accountsservice-0.6.15-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"accountsservice-debuginfo-0.6.15-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"accountsservice-debugsource-0.6.15-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"accountsservice-devel-0.6.15-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"accountsservice-lang-0.6.15-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libaccountsservice0-0.6.15-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libaccountsservice0-debuginfo-0.6.15-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "accountsservice");
}
