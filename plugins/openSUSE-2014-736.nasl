#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-736.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79754);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/09 14:21:16 $");

  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_bugtraq_id(71178, 71242);

  script_name(english:"openSUSE Security Update : clamav (openSUSE-SU-2014:1560-1)");
  script_summary(english:"Check for the openSUSE-2014-736 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"clamav was updated to version 0.98.5 to fix two security issues.

These security issues were fixed :

  - Segmentation fault when processing certain files
    (CVE-2013-6497).

  - Heap-based buffer overflow when scanning crypted PE
    files (CVE-2014-9050).

The following non-security issues were fixed :

  - Support for the XDP file format and extracting,
    decoding, and scanning PDF files within XDP files.

  - Addition of shared library support for LLVM versions 3.1
    - 3.5 for the purpose of just-in-time(JIT) compilation
    of ClamAV bytecode signatures.

  - Enhancements to the clambc command line utility to
    assist ClamAV bytecode signature authors by providing
    introspection into compiled bytecode programs.

  - Resolution of many of the warning messages from ClamAV
    compilation.

  - Improved detection of malicious PE files.

  - ClamAV 0.98.5 now works with OpenSSL in FIPS compliant
    mode (bnc#904207).

  - Fix server socket setup code in clamd (bnc#903489).

  - Change updateclamconf to prefer the state of the old
    config file even for commented-out options (bnc#903719)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906770"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/06");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"clamav-0.98.5-5.30.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"clamav-debuginfo-0.98.5-5.30.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"clamav-debugsource-0.98.5-5.30.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"clamav-0.98.5-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"clamav-debuginfo-0.98.5-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"clamav-debugsource-0.98.5-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"clamav-0.98.5-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"clamav-debuginfo-0.98.5-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"clamav-debugsource-0.98.5-2.5.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-debuginfo / clamav-debugsource");
}
