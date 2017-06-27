#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-229.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75302);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-4408", "CVE-2013-4496");
  script_bugtraq_id(64101, 64191, 66336);

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2014:0405-1)");
  script_summary(english:"Check for the openSUSE-2014-229 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba was updated to fix security issues and bugs :

Security issues fixed :

  - Password lockout was not enforced for SAMR password
    changes, this allowed brute-force attacks on passwords.
    CVE-2013-4496; (bnc#849224).

  - The DCE-RPC fragment length field is incorrectly
    checked, which could expose samba clients to buffer
    overflow exploits caused by malicious servers;
    CVE-2013-4408; (bnc#844720).

  - The pam_winbind login without require_membership_of
    restrictions could allow fallbacks to local users even
    if they were not intended to be allowed; CVE-2012-6150;
    (bnc#853347).

Also non security bugs were fixed :

  - Fix problem with server taking too long to respond to a
    MSG_PRINTER_DRVUPGRADE message; (bso#9942);
    (bnc#863748).

  - Fix memory leak in printer_list_get_printer();
    (bso#9993); (bnc#865561).

  - Depend on %version-%release with all manual Provides and
    Requires; (bnc#844307).

  - Remove superfluous obsoletes *-64bit in the ifarch ppc64
    case; (bnc#437293).

  - Fix Winbind 100% CPU utilization caused by domain list
    corruption; (bso#10358); (bnc#786677).

  - Samba is chatty about being unable to open a printer;
    (bso#10118).

  - nsswitch: Fix short writes in winbind_write_sock;
    (bso#10195).

  - xattr: fix listing EAs on *BSD for non-root users;
    (bso#10247).

  - spoolss: accept XPS_PASS datatype used by Windows 8;
    (bso#10267).

  - The preceding bugs are tracked by (bnc#854520) too.

  - Make use of the full gpg pub key file name including the
    key ID.

  - Remove bogus libsmbclient0 package description and
    cleanup the libsmbclient line from baselibs.conf;
    (bnc#853021).

  - Allow smbcacls to take a '--propagate-inheritance' flag
    to indicate that the add, delete, modify and set
    operations now support automatic propagation of
    inheritable ACE(s); (FATE#316474).

  - Attempt to use samlogon validation level 6; (bso#7945);
    (bnc#741623).

  - Recover from ncacn_ip_tcp ACCESS_DENIED/SEC_PKG_ERROR
    lsa errors; (bso#7944); (bnc#755663).

  - Fix lsa_LookupSids3 and lsa_LookupNames4 arguments.

  - Use simplified smb signing infrastructure; (bnc#741623)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=437293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865561"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libnetapi-devel-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient-devel-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes-devel-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient-devel-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debugsource-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-devel-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-debuginfo-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.12-59.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.12-59.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
