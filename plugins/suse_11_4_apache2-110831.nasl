#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-5089.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75786);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);
  script_osvdb_id(74721);

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2011:0993-1)");
  script_summary(english:"Check for the apache2-5089 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a remote denial of service bug (memory exhaustion)
in the Apache 2 HTTP server, that could be triggered by remote
attackers using multiple overlapping Request Ranges . (CVE-2011-3192)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"apache2-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-debuginfo-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-debugsource-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-devel-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-example-certificates-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-example-pages-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-itk-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-itk-debuginfo-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-prefork-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-prefork-debuginfo-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-utils-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-utils-debuginfo-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-worker-2.2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-worker-debuginfo-2.2.17-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2");
}
