#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-326.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89909);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2016-1531");

  script_name(english:"openSUSE Security Update : exim (openSUSE-2016-326)");
  script_summary(english:"Check for the openSUSE-2016-326 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to exim 4.86.2 fixes the following issues :

  - CVE-2016-1531: local privilege escalation for set-uid
    root exim when using 'perl_startup' (boo#968844)

Important: Exim now cleans the complete execution environment by
default. This affects Exim and subprocesses such as transports calling
other programs. The following new options are supported to adjust this
behaviour :

  - keep_environment

  - add_environment A warning will be printed upon startup
    if none of these are configured.

Also includes upstream changes, improvements and bug fixes :

  - Support for using the system standard CA bundle.

  - New expansion items $config_file, $config_dir,
    containing the file and directory name of the main
    configuration file. Also $exim_version.

  - New 'malware=' support for Avast.

  - New 'spam=' variant option for Rspamd.

  - Assorted options on malware= and spam= scanners.

  - A commandline option to write a comment into the
    logfile.

  - A logging option for slow DNS lookups.

  - New ${env {<variable>}} expansion.

  - A non-SMTP authenticator using information from TLS
    client certificates.

  - Main option 'tls_eccurve' for selecting an Elliptic
    Curve for TLS.

  - Main option 'dns_trust_aa' for trusting your local
    nameserver at the same level as DNSSEC."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968844"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximstats-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"exim-4.86.2-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"exim-debuginfo-4.86.2-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"exim-debugsource-4.86.2-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"eximon-4.86.2-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"eximon-debuginfo-4.86.2-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"eximstats-html-4.86.2-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"exim-4.86.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"exim-debuginfo-4.86.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"exim-debugsource-4.86.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"eximon-4.86.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"eximon-debuginfo-4.86.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"eximstats-html-4.86.2-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-debugsource / eximon / etc");
}
