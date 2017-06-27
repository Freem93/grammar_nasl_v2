#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update samba-1830.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27426);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:36:49 $");

  script_cve_id("CVE-2006-3403");

  script_name(english:"openSUSE 10 Security Update : samba (samba-1830)");
  script_summary(english:"Check for the samba-1830 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Prevent potential crash in winbindd's credential cache
    handling; [#184450].

  - Fix memory exhaustion DoS; CVE-2006-3403; [#190468].

  - Fix the munlock call, samba.org svn rev r16755 from
    Volker.

  - Change the kerberos principal for LDAP authentication to
    netbios-name$@realm from host/name@realm; [#184450].

  - Ensure to link all required libraries to libnss_wins;
    [#184306].

  - Change log level of debug message to avaoid flodded nmbd
    log; [#157623].

  - Add 'usershare allow guests = Yes' to the default
    config; [#144787].

  - Add CHANGEPW kpasswd fallback to TCP; [#184945].

  - Honour 'sn' attribute for eDir; [#176799].

  - Adapt smbclient fix to smbtree to enable long share
    names; [#175999].

  - Make smbclient -L use RPC to list shares, fall back to
    RAP; [#171311].

  - Re-add in-forest domain trusts; [bso #3823].

  - Remove SO_SNDBUF and SO_RCVBUF from socket options
    example; [#165723].

  - Add wbinfo --own-domain; [#167344].

  - Fix usability of pam_winbind on a Samba PDC; [bso
    #3800].

  - Remove intrusive affinity patches for winbindd.

  - Merge Volker's winbindd crash fix for half-opened
    connections in winbindd_cm.c (sessionsetup succeeded but
    tconX failed).

  - Optimize lookup of user's group memberships via
    ExtendedDn LDAP control; [#168100].

  - Restart winbind if the hostname is modified by the DHCP
    client; [#169260].

  - Prevent passwords beeing swapped to disc; [#174834].

  - Remove length limit from winbind cache cleanup function;
    [#175737].

  - Fix NDS_ldapsam memory leak.

  - Only add password to linked list when necessary.

  - Don't try cached credentials when changing passwords.

  - Cleanup winbind linked list of credential caches.

  - Use the index objectCategory attribute in AD LDAP
    requests.

  - Adjust AD time difference when validating tickets.

  - Add password change warning for passwords beeing too
    young.

  - Remove experimental Heimdal KCM support.

  - Added 'usershare allow guests' global parameter;
    [#144787].

  - Return domain name in samrquerydominfo 5; [#172756].

  - Fix unauthorized access when logging in with
    pam_winbind; [#156385].

  - Don't ever set O_SYNC on open unless 'strict sync =
    yes'; [#165431].

  - Correct fix to exit from 'net' with an inproper
    configuration; [#163227], [#182749]."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"samba-3.0.22-13.18") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-client-3.0.22-13.18") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-winbind-3.0.22-13.18") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-32bit-3.0.22-13.18") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.18") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.18") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
