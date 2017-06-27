#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-284.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97292);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2016-7055", "CVE-2017-3731", "CVE-2017-3732");

  script_name(english:"openSUSE Security Update : nodejs (openSUSE-2017-284)");
  script_summary(english:"Check for the openSUSE-2017-284 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"nodejs was updated to LTS release 4.7.3 to fix the following issues :

  - deps: upgrade embedded openssl sources to 1.0.2k
    (CVE-2017-3731, CVE-2017-3732, CVE-2016-7055,
    boo#1022085, boo#1022086, boo#1009528)

Changes in LTS release 4.7.1 :

  - build: shared library support is now working for AIX
    builds

  - repl: passing options to the repl will no longer
    overwrite defaults

  - timers: recanceling a cancelled timers will no longer
    throw

Changes in LTS release 4.7.0 :

  - build: introduce the configure --shared option for
    embedders

  - debugger: make listen address configurable in debugger
    server

  - dgram: generalized send queue to handle close, fixing a
    potential throw when dgram socket is closed in the
    listening event handler

  - http: introduce the 451 status code 'Unavailable For
Legal Reasons'

  - gtest: the test reporter now outputs tap comments as
    yamlish

  - tls: introduce secureContext for tls.connect (useful for
    caching client certificates, key, and CA certificates)

  - tls: fix memory leak when writing data to TLSWrap
    instance during handshake

  - src: node no longer aborts when c-ares initialization
    fails

Changes in LTS release 4.6.2 :

  - build: it is now possible to build the documentation
    from the release tarball

  - buffer: Buffer.alloc() will no longer incorrectly return
    a zero filled buffer when an encoding is passed

  - deps/npm: upgrade npm in LTS to 2.15.11

  - repl: enable tab completion for global properties

  - url: url.format() will now encode all '#' in search"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"nodejs-4.7.3-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debuginfo-4.7.3-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debugsource-4.7.3-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-devel-4.7.3-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"npm-4.7.3-39.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / npm");
}
