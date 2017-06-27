#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-304.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74960);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-5783");

  script_name(english:"openSUSE Security Update : jakarta-commons-httpclient (openSUSE-SU-2013:0622-1)");
  script_summary(english:"Check for the openSUSE-2013-304 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"jakarta-commons-httpclient was updated to enhance the fix of
bnc#803332 / CVE-2012-5783

  - also check for subjectAltNames in the certificate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-commons-httpclient packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-commons-httpclient-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-commons-httpclient-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-commons-httpclient-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"jakarta-commons-httpclient-3.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"jakarta-commons-httpclient-demo-3.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"jakarta-commons-httpclient-javadoc-3.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"jakarta-commons-httpclient-manual-3.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"jakarta-commons-httpclient-3.1-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"jakarta-commons-httpclient-demo-3.1-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"jakarta-commons-httpclient-javadoc-3.1-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"jakarta-commons-httpclient-manual-3.1-4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-httpclient");
}
