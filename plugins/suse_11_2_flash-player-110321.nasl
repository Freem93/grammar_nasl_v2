#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update flash-player-4187.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53720);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:00:35 $");

  script_cve_id("CVE-2011-0609");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2011:0215-1)");
  script_summary(english:"Check for the flash-player-4187 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Adobe Flash Player was updated to the 10.2.153.1, fixing several
bugs and one security issue. 

This vulnerability (CVE-2011-0609) could cause a crash and potentially
allow an attacker to take control of the affected system. There are
reports that this vulnerability is being exploited in the wild in
targeted attacks via a Flash (.swf) file embedded in a Microsoft Excel
(.xls) file delivered as an email attachment."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-03/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679672"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player AVM Bytecode Verification Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"flash-player-10.2.153.1-0.2.1") ) flag++;

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
