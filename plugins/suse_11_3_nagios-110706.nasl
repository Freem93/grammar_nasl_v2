#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update nagios-4838.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75676);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-1523");

  script_name(english:"openSUSE Security Update : nagios (openSUSE-SU-2011:0833-1)");
  script_summary(english:"Check for the nagios-4838 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"statusmap.cgi was prone to a cross-site scripting (XSS) vulnerability
(CVE-2011-1523)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-07/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=682966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagios packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/06");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"nagios-3.2.1-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"nagios-devel-3.2.1-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"nagios-www-3.2.1-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios / nagios-devel / nagios-www");
}
