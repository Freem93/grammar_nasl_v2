#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update lighttpd-5735.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75941);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-4362");
  script_osvdb_id(77366);

  script_name(english:"openSUSE Security Update : lighttpd (openSUSE-SU-2012:0240-1)");
  script_summary(english:"Check for the lighttpd-5735 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of lighttpd fixes an out-of-bounds read due to a
signedness error which could cause a Denial of Service
(CVE-2011-4362). Additionally an option was added to honor the server
cipher order (resolves lighttpd#2364)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-02/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-debuginfo-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-debugsource-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_cml-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_cml-debuginfo-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_magnet-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_magnet-debuginfo-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_mysql_vhost-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_rrdtool-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_trigger_b4_dl-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_webdav-1.4.26-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"lighttpd-mod_webdav-debuginfo-1.4.26-6.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-mod_cml / lighttpd-mod_magnet / etc");
}
