#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update glibc-3399.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(50367);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2008-1391", "CVE-2010-0015", "CVE-2010-0296", "CVE-2010-0830", "CVE-2010-3847", "CVE-2010-3856");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-SU-2010:0914-1)");
  script_summary(english:"Check for the glibc-3399 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of glibc fixes various bugs and security issues :

CVE-2010-3847: Decoding of the $ORIGIN special value in various LD_
environment variables allowed local attackers to execute code in
context of e.g. setuid root programs, elevating privileges. This issue
does not affect SUSE as an assertion triggers before the respective
code is executed. The bug was fixed nevertheless.

CVE-2010-3856: The LD_AUDIT environment was not pruned during setuid
root execution and could load shared libraries from standard system
library paths. This could be used by local attackers to inject code
into setuid root programs and so elevated privileges.

CVE-2010-0830: Integer overflow causing arbitrary code execution in
ld.so

--verify mode could be induced by a specially crafted binary.

CVE-2010-0296: The addmntent() function would not escape the newline
character properly, allowing the user to insert arbitrary newlines to
the /etc/mtab; if the addmntent() is run by a setuid mount binary that
does not do extra input checking, this would allow custom entries to
be inserted in /etc/mtab.

CVE-2008-1391: The strfmon() function contains an integer overflow
vulnerability in width specifiers handling that could be triggered by
an attacker that can control the format string passed to strfmon().

CVE-2010-0015: Some setups (mainly Solaris-based legacy setups)
include shadow information (password hashes) as so-called 'adjunct
passwd' table, mangling it with the rest of passwd columns instead of
keeping it in the shadow table. Normally, Solaris will disclose this
information only to clients bound to a priviledged port, but when nscd
is deployed on the client, getpwnam() would disclose the password
hashes to all users. New mode 'adjunct as shadow' can now be enabled
in /etc/default/nss that will move the password hashes from the
world-readable passwd table to emulated shadow table (that is not
cached by nscd).

Some invalid behaviour, crashes and memory leaks were fixed :

  - statfs64() would not function properly on IA64 in ia32el
    emulation mode.

  - memcpy() and memset() on power6 would erroneously use a
    64-bit instruction within 32-bit code in certain corner
    cases.

  - nscd would not load /etc/host.conf properly before
    performing host resolution - most importantly, `multi
    on` in /etc/host.conf would be ignored when nscd was
    used, breaking e.g. resolving records in /etc/hosts
    where single name would point at multiple addresses

  - Removed mapping from lowercase sharp s to uppercase
    sharp S; uppercase S is not a standardly used letter and
    causes problems for ISO encodings.

Some other minor issues were fixed :

  - glibc-locale now better coexists with sap-locale on
    upgrades by regenerating the locale/gconv indexes
    properly.

  - Ports 623 and 664 may not be allocated by RPC code
    automatically anymore since that may clash with ports
    used on some IPMI network cards.

  - On x86_64, backtrace of a static destructor would stop
    in the _fini() glibc pseudo-routine, making it difficult
    to find out what originally triggered the program
    termination. The routine now has unwind information
    attached."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-10/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=375315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=445636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=513961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=538067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=572188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=585879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=594263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=646960"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(189, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"glibc-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-devel-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-html-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-i18ndata-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-info-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-locale-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-obsolete-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glibc-profile-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"nscd-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"glibc-32bit-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"glibc-devel-32bit-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"glibc-locale-32bit-2.9-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"glibc-profile-32bit-2.9-2.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
