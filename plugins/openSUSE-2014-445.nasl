#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-445.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76336);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/02 11:22:13 $");

  script_cve_id("CVE-2014-0107");

  script_name(english:"openSUSE Security Update : xalan-j2 (openSUSE-SU-2014:0861-1)");
  script_summary(english:"Check for the openSUSE-2014-445 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xalan-j2 was updated to ensure secure processing can't be circumvented
(CVE-2014-0107)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-07/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870082"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xalan-j2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-xsltc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"xalan-j2-2.7.0-259.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xalan-j2-demo-2.7.0-259.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xalan-j2-javadoc-2.7.0-259.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xalan-j2-manual-2.7.0-259.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xalan-j2-xsltc-2.7.0-259.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-2.7.0-262.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-demo-2.7.0-262.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-manual-2.7.0-262.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-xsltc-2.7.0-262.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xalan-j2");
}
