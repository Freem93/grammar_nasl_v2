#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-635.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86285);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-3183", "CVE-2015-3185", "CVE-2015-4000");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2015-635) (Logjam)");
  script_summary(english:"Check for the openSUSE-2015-635 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache2 was updated to fix security issues.

  - CVE-2015-3185: The ap_some_auth_required function in
    server/request.c in the Apache HTTP Server 2.4.x did not
    consider that a Require directive may be associated with
    an authorization setting rather than an authentication
    setting, which allows remote attackers to bypass
    intended access restrictions in opportunistic
    circumstances by leveraging the presence of a module
    that relies on the 2.2 API behavior. [bnc#938723]

  - CVE-2015-3183: The chunked transfer coding
    implementation in the Apache HTTP Server did not
    properly parse chunk headers, which allows remote
    attackers to conduct HTTP request smuggling attacks via
    a crafted request, related to mishandling of large
    chunk-size values and invalid chunk-extension characters
    in modules/http/http_filters.c. [bnc#938728]

On openSUSE 13.1 :

  - CVE-2015-4000: Fix Logjam vulnerability: change the
    default SSLCipherSuite cipherstring to disable export
    cipher suites and deploy Ephemeral Elliptic-Curve
    Diffie-Hellman (ECDHE) ciphers. Adjust 'gensslcert'
    script to generate a strong and unique Diffie Hellman
    Group and append it to the server certificate file
    [bnc#931723]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"apache2-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-debuginfo-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-debugsource-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-devel-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-event-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-event-debuginfo-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-example-pages-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-prefork-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-prefork-debuginfo-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-utils-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-utils-debuginfo-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-worker-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-worker-debuginfo-2.4.6-6.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-debuginfo-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-debugsource-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-devel-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-event-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-event-debuginfo-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-example-pages-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-prefork-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-prefork-debuginfo-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-utils-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-utils-debuginfo-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-worker-2.4.10-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-worker-debuginfo-2.4.10-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
