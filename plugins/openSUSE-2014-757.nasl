#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-757.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79819);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/16 15:13:15 $");

  script_cve_id("CVE-2014-6407", "CVE-2014-6408");

  script_name(english:"openSUSE Security Update : docker (openSUSE-SU-2014:1596-1)");
  script_summary(english:"Check for the openSUSE-2014-757 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"docker was updated to version 1.3.2 to fix two security issues.

These security issues were fixed :

  - Symbolic and hardlink issues leading to privilege
    escalation (CVE-2014-6407).

  - Potential container escalation (CVE-2014-6408).

There non-security issues were fixed :

  - Fix deadlock in docker ps -f exited=1

  - Fix a bug when --volumes-from references a container
    that failed to start

  - --insecure-registry now accepts CIDR notation such as
    10.1.0.0/16

  - Private registries whose IPs fall in the 127.0.0.0/8
    range do no need the --insecure-registry flag

  - Skip the experimental registry v2 API when mirroring is
    enabled

  - Fixed minor packaging issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907014"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"docker-1.3.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-bash-completion-1.3.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-debuginfo-1.3.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-debugsource-1.3.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-zsh-completion-1.3.2-9.1") ) flag++;

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
