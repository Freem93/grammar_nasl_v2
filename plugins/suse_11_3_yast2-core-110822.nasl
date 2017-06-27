#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update yast2-core-5028.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75781);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:32 $");

  script_cve_id("CVE-2011-2483");

  script_name(english:"openSUSE Security Update : yast2-core (openSUSE-SU-2011:0921-2)");
  script_summary(english:"Check for the yast2-core-5028 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update contains yast2 core changes to change the hash generation
of new passwords to the new secure style.

Please read the general notes below :

The implementation of the blowfish based password hashing method had a
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

System logins using PAM have a compat mode enabled by
default: $2x -> buggy algorithm $2a -> buggy algorithm $2y

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
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=700876"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected yast2-core packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-core-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/22");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"yast2-core-2.19.4-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"yast2-core-devel-2.19.4-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "yast2-core");
}
