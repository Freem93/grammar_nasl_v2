#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-184.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96919);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/01 15:04:46 $");

  script_cve_id("CVE-2016-10009", "CVE-2016-10010", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-8858");

  script_name(english:"openSUSE Security Update : openssh (openSUSE-2017-184)");
  script_summary(english:"Check for the openSUSE-2017-184 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssh fixes several issues.

These security issues were fixed :

  - CVE-2016-8858: The kex_input_kexinit function in kex.c
    allowed remote attackers to cause a denial of service
    (memory consumption) by sending many duplicate KEXINIT
    requests (bsc#1005480).

  - CVE-2016-10012: The shared memory manager (associated
    with pre-authentication compression) did not ensure that
    a bounds check is enforced by all compilers, which might
    allowed local users to gain privileges by leveraging
    access to a sandboxed privilege-separation process,
    related to the m_zback and m_zlib data structures
    (bsc#1016370).

  - CVE-2016-10009: Untrusted search path vulnerability in
    ssh-agent.c allowed remote attackers to execute
    arbitrary local PKCS#11 modules by leveraging control
    over a forwarded agent-socket (bsc#1016366).

  - CVE-2016-10010: When forwarding unix domain sockets with
    privilege separation disabled, the resulting sockets
    have be created as 'root' instead of the authenticated
    user. Forwarding unix domain sockets without privilege
    separation enabled is now rejected.

  - CVE-2016-10011: authfile.c in sshd did not properly
    consider the effects of realloc on buffer contents,
    which might allowed local users to obtain sensitive
    private-key information by leveraging access to a
    privilege-separated child process (bsc#1016369).

These non-security issues were fixed :

  - Adjusted suggested command for removing conflicting
    server keys from the known_hosts file (bsc#1006221)

  - Properly verify CIDR masks in configuration (bsc#1005893
    bsc#1021626)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"openssh-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-askpass-gnome-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-askpass-gnome-debuginfo-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-cavs-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-debuginfo-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-debugsource-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-fips-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-helpers-7.2p2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssh-helpers-debuginfo-7.2p2-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-askpass-gnome / openssh-askpass-gnome-debuginfo / openssh / etc");
}
