#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-90.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75214);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/14 16:13:01 $");

  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960", "CVE-2012-5961", "CVE-2012-5962", "CVE-2012-5963", "CVE-2012-5964", "CVE-2012-5965");
  script_osvdb_id(89611, 90578, 97337, 97338);
  script_xref(name:"TRA", value:"TRA-2017-10");

  script_name(english:"openSUSE Security Update : libupnp (openSUSE-SU-2013:0255-1)");
  script_summary(english:"Check for the openSUSE-2013-90 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 1.6.18 (bnc#801061)

  + Security fix for CERT issue VU#922681 This patch
    addresses three possible buffer overflows in function
    unique_service_name(). The three issues have the
    folowing CVE numbers: CVE-2012-5958 Issue #2:
    Stack-based buffer overflow of Tempbuf CVE-2012-5959
    Issue #4: Stack-based buffer overflow of Event->UDN
    CVE-2012-5960 Issue #8: Stack-based buffer overflow of
    Event->UDN

  + Notice that the following issues have already been dealt
    by previous work: CVE-2012-5961 Issue #1: Stack-based
    buffer overflow of Evt->UDN CVE-2012-5962 Issue #3:
    Stack-based buffer overflow of Evt->DeviceType
    CVE-2012-5963 Issue #5: Stack-based buffer overflow of
    Event->UDN CVE-2012-5964 Issue #6: Stack-based buffer
    overflow of Event->DeviceType CVE-2012-5965 Issue #7:
    Stack-based buffer overflow of Event->DeviceType"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libupnp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Portable UPnP SDK unique_service_name() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupnp6-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libupnp-devel-1.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libupnp6-1.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libupnp6-debuginfo-1.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libupnp6-debugsource-1.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libupnp6-32bit-1.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libupnp6-debuginfo-32bit-1.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libupnp-debugsource-1.6.18-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libupnp-devel-1.6.18-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libupnp6-1.6.18-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libupnp6-debuginfo-1.6.18-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libupnp6-32bit-1.6.18-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libupnp6-debuginfo-32bit-1.6.18-6.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libupnp-devel / libupnp6 / libupnp6-32bit / libupnp6-debuginfo / etc");
}
