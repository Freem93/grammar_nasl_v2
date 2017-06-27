#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-1030.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74874);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-4566");

  script_name(english:"openSUSE Security Update : apache2-mod_nss (openSUSE-SU-2013:1956-1)");
  script_summary(english:"Check for the openSUSE-2013-1030 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - mod_nss-CVE-2013-4566-NSSVerifyClient.diff fixes
    CVE-2013-4566: If 'NSSVerifyClient none' is set in the
    server / vhost context (i.e. when server is configured
    to not request or require client certificate
    authentication on the initial connection), and client
    certificate authentication is expected to be required
    for a specific directory via 'NSSVerifyClient require'
    setting, mod_nss fails to properly require certificate
    authentication. Remote attacker can use this to access
    content of the restricted directories. [bnc#853039]

  - glue documentation added to
    /etc/apache2/conf.d/mod_nss.conf :

  - simultaneaous usage of mod_ssl and mod_nss

  - SNI concurrency

  - SUSE framework for apache configuration, Listen
    directive

  - module initialization

  - mod_nss-conf.patch obsoleted by scratch-version of
    nss.conf.in or mod_nss.conf, respectively. This also
    leads to the removal of nss.conf.in specific chunks in
    mod_nss-negotiate.patch and mod_nss-tlsv1_1.patch .

  - mod_nss_migrate.pl conversion script added; not patched
    from source, but partially rewritten.

  - README-SUSE.txt added with step-by-step instructions on
    how to convert and manage certificates and keys, as well
    as a rationale about why mod_nss was included in SLES.

  - package ready for submission [bnc#847216]

  - generic cleanup of the package :

  - explicit Requires: to mozilla-nss >= 3.15.1, as TLS-1.2
    support came with this version - this is the objective
    behind this version update of apache2-mod_nss. Tracker
    bug [bnc#847216]

  - change path /etc/apache2/alias to /etc/apache2/mod_nss.d
    to avoid ambiguously interpreted name of directory.

  - merge content of /etc/apache2/alias to
    /etc/apache2/mod_nss.d if /etc/apache2/alias exists.

  - set explicit filemodes 640 for %post generated *.db
    files in /etc/apache2/mod_nss.d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00118.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853039"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
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

if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_nss-1.0.8-0.4.6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_nss-debuginfo-1.0.8-0.4.6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_nss-debugsource-1.0.8-0.4.6.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_nss / apache2-mod_nss-debuginfo / etc");
}
