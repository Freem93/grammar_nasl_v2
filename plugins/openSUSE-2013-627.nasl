#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-627.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75105);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_osvdb_id(95657);

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-SU-2013:1294-1)");
  script_summary(english:"Check for the openSUSE-2013-627 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libgcrypt was updated to 1.5.3 [bnc#831359] to fix a security issue,
bugs and get some new features :

Security issue fixed :

  - Mitigate the Yarom/Falkner flush+reload side-channel
    attack on RSA secret keys. See
    <http://eprint.iacr.org/2013/448>.

  - contains changes from 1.5.2

  - The upstream sources now contain the IDEA algorithm,
    dropping: idea.c.gz libgcrypt-1.5.0-idea.patch
    libgcrypt-1.5.0-idea_codecleanup.patch

  - Made the Padlock code work again (regression since
    1.5.0).

  - Fixed alignment problems for Serpent.

  - Fixed two bugs in ECC computations.

  - add GPL3.0+ to License tag because of dumpsexp
    (bnc#810759) 

  - contains changes from 1.5.1

  - Allow empty passphrase with PBKDF2.

  - Do not abort on an invalid algorithm number in
    gcry_cipher_get_algo_keylen and
    gcry_cipher_get_algo_blklen.

  - Fixed some Valgrind warnings.

  - Fixed a problem with select and high fd numbers.

  - Improved the build system

  - Various minor bug fixes.

  - Interface changes relative to the 1.5.0 release:
    GCRYCTL_SET_ENFORCED_FIPS_FLAG NEW.
    GCRYPT_VERSION_NUMBER NEW."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://eprint.iacr.org/2013/448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831359"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libgcrypt-debugsource-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgcrypt-devel-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgcrypt-devel-debuginfo-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgcrypt11-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgcrypt11-debuginfo-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgcrypt11-32bit-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgcrypt11-debuginfo-32bit-1.5.3-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt-debugsource-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt-devel-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt-devel-debuginfo-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt11-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt11-debuginfo-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt11-32bit-1.5.3-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt11-debuginfo-32bit-1.5.3-12.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt");
}
