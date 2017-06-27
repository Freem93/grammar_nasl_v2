#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-257.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75308);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_bugtraq_id(66153, 66157);

  script_name(english:"openSUSE Security Update : lighttpd (openSUSE-SU-2014:0449-1)");
  script_summary(english:"Check for the openSUSE-2014-257 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"lighttpd was updated to version 1.4.35, fixing bugs and security
issues :

CVE-2014-2323: SQL injection vulnerability in mod_mysql_vhost.c in
lighttpd allowed remote attackers to execute arbitrary SQL commands
via the host name, related to request_check_hostname.

CVE-2014-2323: Multiple directory traversal vulnerabilities in (1)
mod_evhost and (2) mod_simple_vhost in lighttpd allowed remote
attackers to read arbitrary files via a .. (dot dot) in the host name,
related to request_check_hostname.

More information can be found on the lighttpd advisory page:
http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt 

Other changes :

  - [network/ssl] fix build error if TLSEXT is disabled

  - [mod_fastcgi] fix use after free (only triggered if
    fastcgi debug is active)

  - [mod_rrdtool] fix invalid read (string not null
    terminated)

  - [mod_dirlisting] fix memory leak if pcre fails

  - [mod_fastcgi,mod_scgi] fix resource leaks on spawning
    backends

  - [mod_magnet] fix memory leak

  - add comments for switch fall throughs

  - remove logical dead code

  - [buffer] fix length check in buffer_is_equal_right_len

  - fix resource leaks in error cases on config parsing and
    other initializations

  - add force_assert() to enforce assertions as simple
    assert()s are disabled by -DNDEBUG (fixes #2546)

  - [mod_cml_lua] fix NULL pointer dereference

  - force assertion: setting FD_CLOEXEC must work (if
    available)

  - [network] check return value of lseek()

  - fix unchecked return values from
    stream_open/stat_cache_get_entry

  - [mod_webdav] fix logic error in handling file creation
    error

  - check length of unix domain socket filenames

  - fix SQL injection / host name validation (thx Jann Horn)
    for all the changes see
    /usr/share/doc/packages/lighttpd/NEWS"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867350"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/19");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-debugsource-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_cml-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_cml-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_geoip-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_geoip-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_magnet-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_magnet-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_mysql_vhost-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_rrdtool-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_trigger_b4_dl-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_webdav-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lighttpd-mod_webdav-debuginfo-1.4.35-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-debugsource-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_cml-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_cml-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_geoip-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_geoip-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_magnet-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_magnet-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_mysql_vhost-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_rrdtool-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_trigger_b4_dl-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_webdav-1.4.35-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lighttpd-mod_webdav-debuginfo-1.4.35-2.9.1") ) flag++;

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
