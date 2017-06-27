#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

# @DEPRECATED@
#
# This script has been deprecated as it duplicates plugin #58576
# (suse_glibc-blowfish-7663.nasl).
#
# Disabled on 2013/12/05.
#

include("compat.inc");

if (description)
{
  script_id(57202);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/12/05 17:03:16 $");

  script_cve_id("CVE-2011-2483");

  script_name(english:"SuSE 10 Security Update : glibc (ZYPP Patch Number 7663) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The implementation of the blowfish based password hashing method had a
bug affecting passwords that contain 8bit characters (e.g. umlauts).
Affected passwords are potentially faster to crack via brute-force
methods. (CVE-2011-2483)

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
buggy algorithm $2a -> buggy algorithm $2y -> correct algorithm

Q: How do I require users to change their password on next login? A:
Run the following command as root for each user: chage -d 0

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
    value:"http://support.novell.com/security/cve/CVE-2011-2483.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7663.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The plugin duplicates #58576 (suse_glibc-blowfish-7663.nasl).");


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if ( rpm_check( reference:"glibc-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-devel-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-html-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-i18ndata-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-info-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-locale-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-profile-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"libxcrypt-2.4-12.9.4", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"libxcrypt-devel-2.4-12.9.4", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"nscd-2.4-31.93.1", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"pam-modules-10-2.17.4", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"pwdutils-3.0.7.1-17.36.2", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"pwdutils-plugin-audit-3.0.7.1-17.36.2", release:"SLES10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-devel-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-html-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-i18ndata-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-info-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"glibc-locale-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"libxcrypt-2.4-12.9.4", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"nscd-2.4-31.93.1", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"pam-modules-10-2.17.4", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;
if ( rpm_check( reference:"pwdutils-3.0.7.1-17.36.2", release:"SLED10", cpu:"i586", sp: 4) ) flag ++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
