#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update lighttpd-5107.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31775);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-0983", "CVE-2008-1111", "CVE-2008-1270");

  script_name(english:"openSUSE 10 Security Update : lighttpd (lighttpd-5107)");
  script_summary(english:"Check for the lighttpd-5107 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Remote attackers were able to crash lighttpd by opening
    a large number of connections (CVE-2008-0983).

  - A bug in mod_cgi allowed remote attackers to read cgi
    source files (CVE-2008-1111).

  - A bug in mod_userdir allowed remote attackers to read
    arbitrary files (CVE-2008-1270)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/04");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-1.4.10-11.20") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_cml-1.4.10-11.20") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_mysql_vhost-1.4.10-11.20") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_rrdtool-1.4.10-11.20") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_trigger_b4_dl-1.4.10-11.20") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_webdav-1.4.10-11.20") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_cml-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_magnet-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_mysql_vhost-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_rrdtool-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_trigger_b4_dl-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_webdav-1.4.13-41.8") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-1.4.18-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_cml-1.4.18-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_magnet-1.4.18-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_mysql_vhost-1.4.18-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_rrdtool-1.4.18-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_trigger_b4_dl-1.4.18-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_webdav-1.4.18-1.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-mod_cml / lighttpd-mod_mysql_vhost / etc");
}
