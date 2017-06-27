#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-682.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86623);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/28 14:11:11 $");

  script_cve_id("CVE-2015-3281");

  script_name(english:"openSUSE Security Update : haproxy (openSUSE-2015-682)");
  script_summary(english:"Check for the openSUSE-2015-682 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"haproxy was updated to fix two security issues.

These security issues were fixed :

  - CVE-2015-3281: The buffer_slow_realign function in
    HAProxy did not properly realign a buffer that is used
    for pending outgoing data, which allowed remote
    attackers to obtain sensitive information (uninitialized
    memory contents of previous requests) via a crafted
    request (bsc#937042).

  - Changed DH parameters to prevent Logjam attack.

These non-security issues were fixed :

  - BUG/MAJOR: buffers: make the buffer_slow_realign()
    function respect output data

  - BUG/MINOR: ssl: fix smp_fetch_ssl_fc_session_id

  - MEDIUM: ssl: replace standards DH groups with custom
    ones

  - BUG/MEDIUM: ssl: fix tune.ssl.default-dh-param value
    being overwritten

  - MINOR: ssl: add a destructor to free allocated SSL
    ressources

  - BUG/MINOR: ssl: Display correct filename in error
    message

  - MINOR: ssl: load certificates in alphabetical order

  - BUG/MEDIUM: checks: fix conflicts between agent checks
    and ssl healthchecks

  - BUG/MEDIUM: ssl: force a full GC in case of memory
    shortage

  - BUG/MEDIUM: ssl: fix bad ssl context init can cause
    segfault in case of OOM.

  - BUG/MINOR: ssl: correctly initialize ssl ctx for invalid
    certificates

  - MINOR: ssl: add statement to force some ssl options in
    global.

  - MINOR: ssl: add fetchs 'ssl_c_der' and 'ssl_f_der' to
    return DER formatted certs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937202"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected haproxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/28");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"haproxy-1.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"haproxy-debuginfo-1.5.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"haproxy-debugsource-1.5.5-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "haproxy / haproxy-debuginfo / haproxy-debugsource");
}
