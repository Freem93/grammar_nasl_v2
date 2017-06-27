#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-713.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79575);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/26 11:47:20 $");

  script_cve_id("CVE-2014-7202", "CVE-2014-7203");

  script_name(english:"openSUSE Security Update : zeromq (openSUSE-SU-2014:1493-1)");
  script_summary(english:"Check for the openSUSE-2014-713 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"zeromq was updated to version 4.0.5 to fix two security issues and
various other bugs.

These security issues were fixed :

  - Did not validate the other party's security handshake
    properly, allowing a man-in-the-middle downgrade attack
    (CVE-2014-7202).

  - Did not implement a uniqueness check on connection
    nonces, and the CurveZMQ RFC was ambiguous about nonce
    validation. This allowed replay attacks (CVE-2014-7203).

Other issues fixed in this update :

  - CURVE mechanism does not verify short term nonces.

  - stream_engine is vulnerable to downgrade attacks.

  - assertion failure for WSAENOTSOCK on Windows.

  - race condition while connecting inproc sockets.

  - bump so library number to 4.0.0

  - assertion failed: !more (fq.cpp:99) after many ZAP
    requests.

  - lost first part of message over inproc://."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=898917"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zeromq packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmq4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libzmq4-4.0.5-3.6.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzmq4-debuginfo-4.0.5-3.6.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"zeromq-debugsource-4.0.5-3.6.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"zeromq-devel-4.0.5-3.6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzmq4 / libzmq4-debuginfo / zeromq-debugsource / zeromq-devel");
}
