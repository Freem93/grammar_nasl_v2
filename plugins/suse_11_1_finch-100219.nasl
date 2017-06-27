#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update finch-2032.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44979);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2010-0013", "CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");

  script_name(english:"openSUSE Security Update : finch (finch-2032)");
  script_summary(english:"Check for the finch-2032 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of pidgin fixes various security vulnerabilities

  - CVE-2010-0013: CVSS v2 Base Score: 4.3: Path Traversal
    (CWE-22) Remote file disclosure vulnerability by using
    the MSN protocol.

  - CVE-2010-0277: CVSS v2 Base Score: 4.9: Resource
    Management Errors (CWE-399) MSN protocol plugin in
    libpurple allowed remote attackers to cause a denial of
    service (memory corruption) at least.

  - CVE-2010-0420 Same nick names in XMPP MUC lead to a
    crash in finch.

  - CVE-2010-0423 A remote denial of service attack
    (resource consumption) is possible by sending an IM with
    a lot of smilies in it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected finch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20, 22, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"finch-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"finch-devel-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libpurple-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libpurple-devel-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libpurple-lang-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libpurple-meanwhile-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libpurple-mono-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pidgin-2.6.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pidgin-devel-2.6.6-0.1.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
