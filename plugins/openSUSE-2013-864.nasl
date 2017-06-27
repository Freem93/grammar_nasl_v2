#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-864.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75202);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4484");
  script_bugtraq_id(63451);
  script_osvdb_id(99196);

  script_name(english:"openSUSE Security Update : varnish (openSUSE-SU-2013:1679-1)");
  script_summary(english:"Check for the openSUSE-2013-864 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issue with varnish :

  - bnc#848451, CVE-2013-4484: fixed denial of service flaw
    in certain GET requests when using certain
    configurations in Varnish Cache handling"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848451"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected varnish packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvarnishapi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvarnishapi1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:varnish-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:varnish-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:varnish-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libvarnishapi1-3.0.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvarnishapi1-debuginfo-3.0.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"varnish-3.0.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"varnish-debuginfo-3.0.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"varnish-debugsource-3.0.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"varnish-devel-3.0.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvarnishapi1-3.0.3-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvarnishapi1-debuginfo-3.0.3-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"varnish-3.0.3-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"varnish-debuginfo-3.0.3-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"varnish-debugsource-3.0.3-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"varnish-devel-3.0.3-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvarnishapi1 / libvarnishapi1-debuginfo / varnish / etc");
}
