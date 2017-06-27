#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update samba-2584.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27428);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:36:49 $");

  script_name(english:"openSUSE 10 Security Update : samba (samba-2584)");
  script_summary(english:"Check for the samba-2584 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A logic error in the deferred open code can lead to an infinite loop
in Samba's smbd daemon.

In addition the following changes are included with these packages :

  - Disable broken DCERPC funnel patch; [#242833].

  - Avoid winbind event handler for internal domains.

  - Fix smbcontrol winbind offline; [#223418].

  - Fail on offline pwd change attempts; [#223501].

  - Register check_dom_handler when coming from offline
    mode.

  - Fix pam_winbind passwd changes in online mode.

  - Call set_domain_online in init_domain_list().

  - Winbind cleanup after failure and fix crash bug.

  - Don't register check domain handler for all trusts.

  - Add separate logfile for dc-connect wb child.

  - Only write custom krb5 conf for own domain.

  - Move check domain handler to fork_domain_child.

  - Fix pam_winbind text string typo; [#238496].

  - Support sites without DCs (automatic site coverage);
    [#219793].

  - Fix invalid krb5 cred cache deletion; [#227782].

  - Fix invalid warning in the PAM session close;

  - Fix DC queries for all DCs; [#230963].

  - Fix sitename usage depending on realm; [#195354].

  - Add DCERPC funnel patch; fate [#300768].

  - Fix pam password change with w2k DCs; [#237281].

  - Check from the init script for SAMBA_<daemonname>_ENV
    variable expected to be set in /etc/sysconfig/samba to
    export a particular environment variable before starting
    a daemon. See section 'Setup a particular environment
    for a Samba daemon' from the README file how this
    feature is to use.

  - Remove %config tag from /usr/share/omc/svcinfo.d/*.xml
    files.

  - Fix pam_winbind grace offline logins; [#223501].

  - Fix password expiry message; [#231583].

  - Move XML service description documents; fate [#301712].

  - Disable smbmnt, smbmount, and smbumount for systems
    newer than 10.1.

  - Add XML service description documents; fate [#301712].

  - Move tdb utils to the client package.

  - Fix crash caused by deleting a message dispatch handler
    from inside the handler itself; [#221709].

  - Fix delays in winbindd access when on a non-home
    network; [#222595]."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/08");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"samba-3.0.23d-19.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-client-3.0.23d-19.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-winbind-3.0.23d-19.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-32bit-3.0.23d-19.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-client-32bit-3.0.23d-19.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.23d-19.2") ) flag++;

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
