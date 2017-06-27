#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-365.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83557);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2015-3627", "CVE-2015-3629", "CVE-2015-3630", "CVE-2015-3631");

  script_name(english:"openSUSE Security Update : docker (openSUSE-2015-365)");
  script_summary(english:"Check for the openSUSE-2015-365 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"docker was updated to version 1.6.1 to fix several security and
non-security issues. 

  - Updated to version 1.6.1 (2015-05-07) [bnc#930235]

  - Security

  - Fix read/write /proc paths (CVE-2015-3630)

  - Prohibit VOLUME /proc and VOLUME / (CVE-2015-3631)

  - Fix opening of file-descriptor 1 (CVE-2015-3627)

  - Fix symlink traversal on container respawn allowing
    local privilege escalation (CVE-2015-3629)

  - Prohibit mount of /sys

  - Runtime

  - Update Apparmor policy to not allow mounts

  - Updated libcontainer-apparmor-fixes.patch: adapt patch
    to reflect changes introduced by docker 1.6.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930235"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"docker-1.6.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-bash-completion-1.6.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-debuginfo-1.6.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-debugsource-1.6.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-zsh-completion-1.6.1-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-bash-completion / docker-debuginfo / etc");
}
