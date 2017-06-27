#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57839);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/12/05 17:10:59 $");

  script_cve_id("CVE-2011-2483");

  script_name(english:"SuSE 11.1 Security Update : glibc (SAT Patch Number 4944)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=645140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=700876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2483.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4944.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libxcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libxcrypt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pam-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pam-modules-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pwdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pwdutils-plugin-audit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"glibc-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"glibc-devel-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"glibc-i18ndata-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"glibc-locale-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libxcrypt-3.0.3-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"nscd-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"pam-modules-11-1.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"pwdutils-3.2.8-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i686", reference:"glibc-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i686", reference:"glibc-devel-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-devel-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-i18ndata-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-locale-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libxcrypt-3.0.3-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libxcrypt-32bit-3.0.3-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"nscd-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"pam-modules-11-1.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"pam-modules-32bit-11-1.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"pwdutils-3.2.8-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-devel-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-html-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-i18ndata-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-info-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-locale-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-profile-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libxcrypt-3.0.3-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"nscd-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"pam-modules-11-1.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"pwdutils-3.2.8-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"pwdutils-plugin-audit-3.2.8-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-devel-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-locale-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-profile-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libxcrypt-32bit-3.0.3-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"pam-modules-32bit-11-1.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.1-0.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libxcrypt-32bit-3.0.3-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"pam-modules-32bit-11-1.18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
