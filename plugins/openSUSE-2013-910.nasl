#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-910.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75215);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4475");
  script_bugtraq_id(63646);

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2013:1787-1)");
  script_summary(english:"Check for the openSUSE-2013-910 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"the following security issues were fixed in samba :

  - ACLs are not checked on opening an alternate data stream
    on a file or directory; CVE-2013-4475; (bso#10229);
    (bnc#848101).

  - Fix memleak in reload_printers_full(); (bso#9993).

  - Valid utf8 filenames cause 'invalid conversion error'
    messages; (bso#10139).

  - s3: smb2 breaks 'smb encryption = mandatory';
    (bso#10167).

  - Missing talloc_free can leak stackframe in error path;
    (bso#10187).

  - Offline logon cache not updating for cross child domain
    group membership; (bso#10194).

  - The preceding bugs are tracked by (bnc#849226) too.

  - Make Samba work on site with Read Only Domain
    Controller; (bso#5917).

  - Give machine password changes 10 minutes of time;
    (bso#8955).

  - NetrServerPasswordSet2 timeout is too short; (bso#8955).

  - Fix fallback to ncacn_np in cm_connect_lsat();
    (bso#9615); (bso#9899).

  - s3-winbind: Do not delete an existing valid credential
    cache; (bso#9994).

  - 'net ads join': Fix segmentation fault in
    create_local_private_krb5_conf_for_domain; (bso#10073).

  - Fix variable list in man vfs_crossrename; (bso#10076).

  - MacOSX 10.9 will not follow path-based DFS referrals
    handed out by Samba; (bso#10097).

  - Honour output buffer length set by the client for SMB2
    GetInfo requests; (bso#10106).

  - Handle Dropbox (write-only-directory) case correctly in
    pathname lookup; (bso#10114).

  - Fix 'smbstatus' as non-root user; (bso#10127).

  - The preceding bugs are tracked by (bnc#849226) too.

  - Windows 8 Roaming profiles fail; (bso#9678).

  - Linux kernel oplock breaks can miss signals;
    (bso#10064).

  - The preceding bugs are tracked by (bnc#849226) too.

  - Verify source tar ball gpg signature.

  - Store and return the correct spoolss jobid in
    notifications; (bnc#838472).

  - Reload snums before processing the printer list.
    (bnc#817880)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849226"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libnetapi-devel-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient-devel-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes-devel-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient-devel-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debugsource-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-devel-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-debuginfo-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.7-48.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi-devel-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient-devel-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes-devel-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient-devel-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debugsource-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-devel-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-debuginfo-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.12-59.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.12-59.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnetapi-devel / libnetapi0 / libnetapi0-debuginfo / etc");
}
