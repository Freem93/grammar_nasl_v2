#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-770.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80043);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/26 04:39:25 $");

  script_cve_id("CVE-2011-3368", "CVE-2012-2687", "CVE-2013-1862", "CVE-2013-1896", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0226", "CVE-2014-0231");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2014:1647-1)");
  script_summary(english:"Check for the openSUSE-2014-770 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This apache version update fixes various security and non security
issues.

  - Updated to the 2.2.29

  - Changes between 2.2.22 and 2.2.29:
    http://www.apache.org/dist/httpd/CHANGES_2.2

  - The following patches are no longer needed and were
    removed :

    - httpd-2.2.x-bnc798733-SNI_ignorecase.diff

    - httpd-2.2.x-bnc806458-mod_imagemap-xss.diff

    - httpd-2.2.x-bnc806458-mod_info_ap_get_server_name-xss.diff

    - httpd-2.2.x-bnc806458-mod_proxy_ftp-xss.diff

    - httpd-2.2.x-bnc806458-util_ldap_cache_mgr-xss.diff

    - httpd-2.2.x-bnc807152-mod_balancer_handler_xss.diff

    - httpd-mod_deflate_head.patch

    - httpd-new_pcre.patch

    - httpd-2.2.22-SSLCompression_CRIME_mitigation.patch

    - httpd-2.2.19-linux3.patch

    - httpd-2.2.x-bnc829056-CVE-2013-1896-pr1482522-mod_dav.diff

    - httpd-2.2.x-bnc829057-CVE-2013-1862-mod_rewrite_terminal_escape_sequences.diff

    - httpd-2.2.x-bnc869105-CVE-2013-6438-mod_dav-dos.diff

    - httpd-2.2.x-bnc869106-CVE-2014-0098-log_cookie_c.diff

    - httpd-2.2.x-bnc887765-CVE-2014-0226-mod_status_race.diff

    - httpd-2.2.x-bnc887768-CVE-2014-0231_mod_cgid_DoS_via_no_stdin_read.diff

    - httpd-2.2.x-bnc777260-CVE-2012-2687-mod_negotiation_filename_xss.diff

    - httpd-2.2.x-CVE-2011-3368-server_protocl_c.diff

  - The following patches were updated for the current
    Apache version :

  - apache2-mod_ssl_npn.patch

    - httpd-2.0.54-envvars.dif

    - httpd-2.2.x-bnc690734.patch

  - ssl-mode-release-buffers.patch

  - bnc#871310 fixed in Apache httpd 2.2.29"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apache.org/dist/httpd/CHANGES_2.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=871310"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"apache2-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-debuginfo-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-debugsource-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-devel-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-event-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-event-debuginfo-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-example-pages-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-itk-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-itk-debuginfo-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-prefork-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-prefork-debuginfo-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-utils-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-utils-debuginfo-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-worker-2.2.29-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-worker-debuginfo-2.2.29-10.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
