#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update lighttpd-4532.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27341);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/06/13 20:31:02 $");

  script_cve_id("CVE-2007-4727");

  script_name(english:"openSUSE 10 Security Update : lighttpd (lighttpd-4532)");
  script_summary(english:"Check for the lighttpd-4532 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a buffer overflow in the fcgi_env_add() function.
Under some circumstances this bug allows remote code execution.
(CVE-2007-4727)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-1.4.10-11.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_cml-1.4.10-11.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_mysql_vhost-1.4.10-11.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_rrdtool-1.4.10-11.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_trigger_b4_dl-1.4.10-11.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"lighttpd-mod_webdav-1.4.10-11.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"lighttpd-1.4.10-11.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"lighttpd-mod_cml-1.4.10-11.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"lighttpd-mod_mysql_vhost-1.4.10-11.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"lighttpd-mod_rrdtool-1.4.10-11.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"lighttpd-mod_trigger_b4_dl-1.4.10-11.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"lighttpd-mod_webdav-1.4.10-11.15") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_cml-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_magnet-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_mysql_vhost-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_rrdtool-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_trigger_b4_dl-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"lighttpd-mod_webdav-1.4.13-41.6") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-1.4.18-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_cml-1.4.18-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_magnet-1.4.18-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_mysql_vhost-1.4.18-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_rrdtool-1.4.18-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_trigger_b4_dl-1.4.18-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"lighttpd-mod_webdav-1.4.18-1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd");
}
