#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update lighttpd-5785.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34812);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");

  script_name(english:"openSUSE 10 Security Update : lighttpd (lighttpd-5785)");
  script_summary(english:"Check for the lighttpd-5785 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various issues have been fixed in lighttpd. CVE-2008-4298,
CVE-2008-4359 and CVE-2008-4360 have been assigned to thess issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_cml-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_magnet-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_mysql_vhost-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_rrdtool-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_trigger_b4_dl-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_webdav-1.4.13-41.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-1.4.18-1.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_cml-1.4.18-1.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_magnet-1.4.18-1.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_mysql_vhost-1.4.18-1.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_rrdtool-1.4.18-1.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_trigger_b4_dl-1.4.18-1.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_webdav-1.4.18-1.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd");
}