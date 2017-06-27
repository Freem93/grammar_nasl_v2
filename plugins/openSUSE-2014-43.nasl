#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-43.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75389);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:48 $");

  script_cve_id("CVE-2013-4508", "CVE-2013-4559", "CVE-2013-4560");
  script_bugtraq_id(63534, 63686, 63688);
  script_osvdb_id(99365, 99759, 99760);

  script_name(english:"openSUSE Security Update : lighttpd (openSUSE-SU-2014:0072-1)");
  script_summary(english:"Check for the openSUSE-2014-43 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - added cve-2013-4508.patch and
    cve-2013-4508-regression-bug729480.patch: (bnc#849059)
    When defining an ssl.cipher-list, it works for the
    'default' HTTPS setup ($SERVER['socket'] 443 block), but
    when you utilize SNI ($HTTP['host'] blocks within the
    $SERVER['socket'] block) the ssl.cipher-list seems to
    not inherit into the host blocks and instead will
    default to include all of the available openssl ciphers
    (except SSL v2/v3 based if those are disabled)

  - added cve-2013-4559.patch (bnc#850468) check success of
    setuid,setgid,setgroups

  - added cve-2013-4560.patch (bnc#850469) FAM: fix use
    after free

  - added cve-2013-4508.patch and
    cve-2013-4508-regression-bug729480.patch: (bnc#849059)
    When defining an ssl.cipher-list, it works for the
    'default' HTTPS setup ($SERVER['socket'] 443 block), but
    when you utilize SNI ($HTTP['host'] blocks within the
    $SERVER['socket'] block) the ssl.cipher-list seems to
    not inherit into the host blocks and instead will
    default to include all of the available openssl ciphers
    (except SSL v2/v3 based if those are disabled)

  - added cve-2013-4559.patch (bnc#850468) check success of
    setuid,setgid,setgroups

  - added cve-2013-4560.patch (bnc#850469) FAM: fix use
    after free

  - added cve-2013-4508.patch and
    cve-2013-4508-regression-bug729480.patch: (bnc#849059)
    When defining an ssl.cipher-list, it works for the
    'default' HTTPS setup ($SERVER['socket'] 443 block), but
    when you utilize SNI ($HTTP['host'] blocks within the
    $SERVER['socket'] block) the ssl.cipher-list seems to
    not inherit into the host blocks and instead will
    default to include all of the available openssl ciphers
    (except SSL v2/v3 based if those are disabled)

  - added cve-2013-4559.patch (bnc#850468) check success of
    setuid,setgid,setgroups

  - added cve-2013-4560.patch (bnc#850469) FAM: fix use
    after free"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850469"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-debugsource-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_cml-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_cml-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_geoip-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_geoip-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_magnet-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_magnet-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_mysql_vhost-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_rrdtool-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_trigger_b4_dl-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_webdav-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_webdav-debuginfo-1.4.31-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-debugsource-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_cml-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_cml-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_geoip-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_geoip-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_magnet-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_magnet-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_mysql_vhost-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_rrdtool-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_trigger_b4_dl-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_webdav-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_webdav-debuginfo-1.4.31-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-debugsource-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_cml-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_cml-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_geoip-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_geoip-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_magnet-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_magnet-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_mysql_vhost-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_rrdtool-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_trigger_b4_dl-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_webdav-1.4.32-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_webdav-debuginfo-1.4.32-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-debugsource / etc");
}
