#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update glibc-4943.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75852);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-2483");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-SU-2011:0921-1)");
  script_summary(english:"Check for the glibc-4943 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The implementation of the blowfish based password hashing method had a
bug affecting passwords that contain 8bit characters (e.g. umlauts).
Affected passwords are potentially faster to crack via brute-force
methods (CVE-2011-2483).

SUSE's crypt() implementation supports the blowfish password hashing
function (id $2a) and system logins by default also use this method.
This update eliminates the bug in the $2a implementation. After
installing the update existing $2a hashes therefore no longer match
hashes generated with the new, correct implementation if the password
contains 8bit characters. For system logins via PAM the pam_unix2
module activates a compat mode and keeps processing existing $2a
hashes with the old algorithm. This ensures no user gets locked out.
New passwords hashes are created with the id '$2y' to unambiguously
identify them as generated with the correct implementation.

Note: To actually migrate hashes to the new algorithm all users are
advised to change passwords after the update.

Services that do not use PAM but do use crypt() to store passwords
using the blowfish hash do not have such a compat mode. That means
users with 8bit passwords that use such services will not be able to
log in anymore after the update. As workaround administrators may edit
the service's password database and change stored hashes from $2a to
$2x. This will result in crypt() using the old algorithm. Users should
be required to change their passwords to make sure they are migrated
to the correct algorithm.

FAQ :

Q: I only use ASCII characters in passwords, am I a affected in any
way? A: No.

Q: What's the meaning of the ids before and after the update? A:
Before the update: $2a -> buggy algorithm

After the update: $2x -> buggy algorithm $2a -> correct algorithm $2y
-> correct algorithm

System logins using PAM have a compat mode enabled by default: $2x ->
buggy algorithm $2a -> buggy algorithm $2y

-> correct algorithm

Q: How do I require users to change their password on next login? A:
Run the following command as root for each user: chage -d 0 <username>

Q: I run an application that has $2a hashes in it's password database.
Some users complain that they can not log in anymore. A: Edit the
password database and change the '$2a' prefix of the affected users'
hashes to '$2x'. They will be able to log in again but should change
their password ASAP.

Q: How do I turn off the compat mode for system logins? A: Set
BLOWFISH_2a2x=no in /etc/default/passwd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=700876"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcrypt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcrypt-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam-modules-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam-modules-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-plugin-audit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-plugin-audit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-rpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-rpasswd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-rpasswd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pwdutils-rpasswd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/29");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"glibc-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-debuginfo-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-debugsource-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-devel-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-devel-debuginfo-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-html-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-i18ndata-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-info-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-locale-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-locale-debuginfo-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-obsolete-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-obsolete-debuginfo-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-profile-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libxcrypt-3.0.3-9.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libxcrypt-debuginfo-3.0.3-9.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libxcrypt-debugsource-3.0.3-9.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libxcrypt-devel-3.0.3-9.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nscd-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nscd-debuginfo-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pam-modules-11.4-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pam-modules-debuginfo-11.4-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pam-modules-debugsource-11.4-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-debuginfo-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-debugsource-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-plugin-audit-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-plugin-audit-debuginfo-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-rpasswd-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"pwdutils-rpasswd-debuginfo-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-12.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libxcrypt-32bit-3.0.3-9.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libxcrypt-debuginfo-32bit-3.0.3-9.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"pam-modules-32bit-11.4-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"pam-modules-debuginfo-32bit-11.4-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"pwdutils-rpasswd-32bit-3.2.14-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"pwdutils-rpasswd-debuginfo-32bit-3.2.14-4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-32bit / glibc-devel / glibc-devel-32bit / glibc-html / etc");
}
