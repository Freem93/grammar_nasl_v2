#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openssh-4579.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27589);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/13 20:31:04 $");

  script_cve_id("CVE-2007-4752");

  script_name(english:"openSUSE 10 Security Update : openssh (openssh-4579)");
  script_summary(english:"Check for the openssh-4579 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a bug in ssh's cookie handling code. It does not
properly handle the situation when an untrusted cookie cannot be
created and uses a trusted X11 cookie instead. This allows attackers
to violate the intended policy and gain privileges by causing an X
client to be treated as trusted. (CVE-2007-4752) Additionally this
update fixes a bug introduced with the last security update for
openssh. When the SSH daemon wrote to stderr (for instance, to warn
about the presence of a deprecated option like
PAMAuthenticationViaKbdInt in its configuration file), SIGALRM was
blocked for SSH sessions. This resulted in problems with processes
which rely on SIGALRM, such as ntpdate."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/30");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"openssh-4.2p1-18.30") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"openssh-askpass-4.2p1-18.30") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"openssh-4.4p1-26") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"openssh-askpass-4.4p1-26") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openssh-4.6p1-58.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openssh-askpass-4.6p1-58.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
