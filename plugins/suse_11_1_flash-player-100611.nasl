#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update flash-player-2542.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46880);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2014/10/24 10:42:17 $");

  script_cve_id("CVE-2008-4546", "CVE-2009-3793", "CVE-2010-1297", "CVE-2010-2160", "CVE-2010-2161", "CVE-2010-2162", "CVE-2010-2163", "CVE-2010-2164", "CVE-2010-2165", "CVE-2010-2166", "CVE-2010-2167", "CVE-2010-2169", "CVE-2010-2170", "CVE-2010-2171", "CVE-2010-2172", "CVE-2010-2173", "CVE-2010-2174", "CVE-2010-2175", "CVE-2010-2176", "CVE-2010-2177", "CVE-2010-2178", "CVE-2010-2179", "CVE-2010-2180", "CVE-2010-2181", "CVE-2010-2182", "CVE-2010-2183", "CVE-2010-2184", "CVE-2010-2185", "CVE-2010-2186", "CVE-2010-2187", "CVE-2010-2188", "CVE-2010-2189");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2010:0321-1)");
  script_summary(english:"Check for the flash-player-2542 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Flash Player update fixes multiple critical security
vulnerabilities which allow an attacker to remotely execute arbitrary
code or to cause a denial of service. The following CVE numbers have
been assigned :

CVE-2008-4546, CVE-2009-3793, CVE-2010-1297, CVE-2010-2160,
CVE-2010-2161, CVE-2010-2162, CVE-2010-2163, CVE-2010-2164,
CVE-2010-2165, CVE-2010-2166, CVE-2010-2167, CVE-2010-2169,
CVE-2010-2170, CVE-2010-2171, CVE-2010-2172, CVE-2010-2173,
CVE-2010-2174, CVE-2010-2175, CVE-2010-2176, CVE-2010-2177,
CVE-2010-2178, CVE-2010-2179, CVE-2010-2180, CVE-2010-2181,
CVE-2010-2182, CVE-2010-2183, CVE-2010-2184, CVE-2010-2185,
CVE-2010-2186, CVE-2010-2187, CVE-2010-2188, CVE-2010-2189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-06/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612063"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"flash-player-10.1.53.64-1.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
