#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-146.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81371);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:32 $");

  script_cve_id("CVE-2014-8767", "CVE-2014-8768", "CVE-2014-8769");

  script_name(english:"openSUSE Security Update : tcpdump (openSUSE-2015-146)");
  script_summary(english:"Check for the openSUSE-2015-146 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"tcpdump was updated to fix three security issues.

These security issues were fixed :

  - CVE-2014-8767: Integer underflow in the olsr_print
    function in tcpdump 3.9.6 through 4.6.2, when in verbose
    mode, allowed remote attackers to cause a denial of
    service (crash) via a crafted length value in an OLSR
    frame (bnc#905870 905871).

  - CVE-2014-8769: tcpdump 3.8 through 4.6.2 might allowed
    remote attackers to obtain sensitive information from
    memory or cause a denial of service (packet loss or
    segmentation fault) via a crafted Ad hoc On-Demand
    Distance Vector (AODV) packet, which triggers an
    out-of-bounds memory access (bnc#905871 905872).

  - CVE-2014-8768: Multiple Integer underflows in the
    geonet_print function in tcpdump 4.5.0 through 4.6.2,
    when in verbose mode, allowed remote attackers to cause
    a denial of service (segmentation fault and crash) via a
    crafted length value in a Geonet frame (bnc#905871)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905872"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"tcpdump-4.4.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tcpdump-debuginfo-4.4.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tcpdump-debugsource-4.4.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tcpdump-4.6.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tcpdump-debuginfo-4.6.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tcpdump-debugsource-4.6.2-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump / tcpdump-debuginfo / tcpdump-debugsource");
}
