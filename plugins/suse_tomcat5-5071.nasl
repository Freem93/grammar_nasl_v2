#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update tomcat5-5071.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31675);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:36:50 $");

  script_cve_id("CVE-2007-1858", "CVE-2007-2449");

  script_name(english:"openSUSE 10 Security Update : tomcat5 (tomcat5-5071)");
  script_summary(english:"Check for the tomcat5-5071 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of tomcat fixes cross-site-scripting bugs (CVE-2007-2449)
as well as it improves the list of supported SSL ciphers
(CVE-2007-1858)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"tomcat5-5.0.30-27.26") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"tomcat5-admin-webapps-5.0.30-27.26") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"tomcat5-webapps-5.0.30-27.26") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"tomcat5-5.0.30-62") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"tomcat5-admin-webapps-5.0.30-62") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"tomcat5-webapps-5.0.30-62") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
