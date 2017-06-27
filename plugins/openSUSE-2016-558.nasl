#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-558.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90910);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/05 16:01:16 $");

  script_name(english:"openSUSE Security Update : xerces-j2 (openSUSE-2016-558)");
  script_summary(english:"Check for the openSUSE-2016-558 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xerces-j2 was updated to fix one security issue.

This security issue was fixed :

  - bsc#814241: Fixed possible DoS through very long
    attribute names"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=814241"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-j2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-xml-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-xml-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"xerces-j2-2.11.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xerces-j2-demo-2.11.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xerces-j2-scripts-2.11.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xerces-j2-xml-apis-2.11.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xerces-j2-xml-resolver-2.11.0-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2 / xerces-j2-demo / xerces-j2-scripts / xerces-j2-xml-apis / etc");
}
