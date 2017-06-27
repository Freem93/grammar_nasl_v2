#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-608.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75098);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2139");

  script_name(english:"openSUSE Security Update : srtp (openSUSE-SU-2013:1258-1)");
  script_summary(english:"Check for the openSUSE-2013-608 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in srtp was fixed which could potentially be used by
attackers to crash srtp using applications and potentially execute
code (CVE-2013-2139, bnc828009)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828009"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected srtp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsrtp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsrtp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:srtp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:srtp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libsrtp1-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsrtp1-debuginfo-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"srtp-debugsource-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"srtp-devel-1.4.4-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "srtp");
}
