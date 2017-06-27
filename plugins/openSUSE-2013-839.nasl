#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-839.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75194);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4421", "CVE-2013-4434");

  script_name(english:"openSUSE Security Update : dropbear (openSUSE-SU-2013:1696-1)");
  script_summary(english:"Check for the openSUSE-2013-839 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dropbear was updated to version 2013.60 to fix following bugs :

  - Fix 'make install' so that it doesn't always install to
    /bin and /sbin

  - Fix 'make install MULTI=1', installing manpages failed

  - Fix 'make install' when scp is included since it has no
    manpage

  - Make --disable-bundled-libtom work

  - used as bug fix release for bnc#845306 - VUL-0:
    CVE-2013-4421 and CVE-2013-4434

  - provided links for download sources

  - employed gpg-offline - verify sources 

  - imported upstream version 2013.59

  - Fix crash from -J command Thanks to Llu&Atilde;&shy;s
    Batlle i Rossell and Arnaud Mouiche for patches

  - Avoid reading too much from /proc/net/rt_cache since
    that causes system slowness. 

  - Improve EOF handling for half-closed connections Thanks
    to Catalin Patulea

  - Send a banner message to report PAM error messages
    intended for the user Patch from Martin Donnelly

  - Limit the size of decompressed payloads, avoids memory
    exhaustion denial of service Thanks to Logan Lamb for
    reporting and investigating it

  - Avoid disclosing existence of valid users through
    inconsistent delays Thanks to Logan Lamb for reporting

  - Update config.guess and config.sub for newer
    architectures

  - Avoid segfault in server for locked accounts

  - 'make install' now installs manpages dropbearkey.8 has
    been renamed to dropbearkey.1 manpage added for
    dropbearconvert

  - Get rid of one second delay when running non-interactive
    commands"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845306"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dropbear packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"dropbear-2013.60-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dropbear-debuginfo-2013.60-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dropbear-debugsource-2013.60-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dropbear / dropbear-debuginfo / dropbear-debugsource");
}
