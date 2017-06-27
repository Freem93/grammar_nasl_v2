#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-442.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99212);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2016-7055", "CVE-2017-3731", "CVE-2017-3732");

  script_name(english:"openSUSE Security Update : nodejs4 (openSUSE-2017-442)");
  script_summary(english:"Check for the openSUSE-2017-442 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs4 fixes the following issues :

  - New upstream LTS release 4.7.3 The embedded openssl
    sources were updated to 1.0.2k (CVE-2017-3731,
    CVE-2017-3732, CVE-2016-7055, bsc#1022085, bsc#1022086,
    bsc#1009528)

  - No changes in LTS version 4.7.2

  - New upstream LTS release 4.7.1

  - build: shared library support is now working for AIX
    builds

  - repl: passing options to the repl will no longer
    overwrite defaults

  - timers: recanceling a cancelled timers will no longer
    throw

  - New upstream LTS version 4.7.0

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

  - ported and updated system CA store for the new node
    crypto code

  - New upstream LTS version 4.6.2

  - build :

  + It is now possible to build the documentation from the
    release tarball.

  - buffer :

  + Buffer.alloc() will no longer incorrectly return a zero
    filled buffer when an encoding is passed.

  - deps :

  + Upgrade npm in LTS to 2.15.11.

  - repl :

  + Enable tab completion for global properties.

  - url :

  + url.format() will now encode all '#' in search.

  - Add missing conflicts to base package. It's not possible
    to have concurrent nodejs installations.

  - enable usage of system certificate store on SLE11SP4 by
    requiring openssl1 (bsc#1000036)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000036"
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
    value:"Update the affected nodejs4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-4.7.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-debuginfo-4.7.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-debugsource-4.7.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-devel-4.7.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"npm4-4.7.3-5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs4 / nodejs4-debuginfo / nodejs4-debugsource / nodejs4-devel / etc");
}
