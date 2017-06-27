#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-221.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81765);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/12 14:23:03 $");

  script_cve_id("CVE-2013-5588", "CVE-2013-5589", "CVE-2014-2326", "CVE-2014-2327", "CVE-2014-2328", "CVE-2014-4002", "CVE-2014-5025", "CVE-2014-5026");

  script_name(english:"openSUSE Security Update : cacti (openSUSE-2015-221)");
  script_summary(english:"Check for the openSUSE-2015-221 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cacti was updated to version 0.8.8c [boo#920399]

This update fixes four vulnerabilities and adds some compatible
features.

  - Security fixes not previously patched :

  - CVE-2014-2326 - XSS issue via CDEF editing

  - CVE-2014-2327 - Cross-site request forgery (CSRF)
    vulnerability

  - CVE-2014-2328 - Remote Command Execution Vulnerability
    in graph export

  - CVE-2014-4002 - XSS issues in multiple files

  - CVE-2014-5025 - XSS issue via data source editing

  - CVE-2014-5026 - XSS issues in multiple files

  - Security fixes now upstream :

  - CVE-2013-5588 - XSS issue via installer or device
    editing

  - CVE-2013-5589 - SQL injection vulnerability in device
    editing

New features :

  - New graph tree view

  - Updated graph list and graph preview

  - Refactor graph tree view to remove GPL incompatible code

  - Updated command line database upgrade utility

  - Graph zooming now from everywhere"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920399"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cacti package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"cacti-0.8.8c-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cacti-0.8.8c-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti");
}
