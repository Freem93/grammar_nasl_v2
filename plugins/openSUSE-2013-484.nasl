#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-484.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75025);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2070");

  script_name(english:"openSUSE Security Update : nginx (openSUSE-SU-2013:1015-1)");
  script_summary(english:"Check for the openSUSE-2013-484 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update for nginx to 1.2.9 includes a security fix and
several bugfixes and feature enhancements. (bnc#821184)

*) Security: contents of worker process memory might be sent to a
client if HTTP backend returned specially crafted response
(CVE-2013-2070); the bug had appeared in 1.1.4.

  - changes with 1.2.8 :

    *) Bugfix: new sessions were not always stored if the
    'ssl_session_cache shared' directive was used and there
    was no free space in shared memory.

    *) Bugfix: responses might hang if subrequests were used
    and a DNS error happened during subrequest processing.

    *) Bugfix: in the ngx_http_mp4_module.

    *) Bugfix: in backend usage accounting.

  - changes with nginx 1.2.7

    *) Change: now if the 'include' directive with mask is
    used on Unix systems, included files are sorted in
    alphabetical order.

    *) Change: the 'add_header' directive adds headers to
    201 responses.

    *) Feature: the 'geo' directive now supports IPv6
    addresses in CIDR notation.

    *) Feature: the 'flush' and 'gzip' parameters of the
    'access_log' directive.

    *) Feature: variables support in the 'auth_basic'
    directive.

    *) Feature: the $pipe, $request_length, $time_iso8601,
    and $time_local variables can now be used not only in
    the 'log_format' directive.

    *) Feature: IPv6 support in the ngx_http_geoip_module.

    *) Bugfix: nginx could not be built with the
    ngx_http_perl_module in some cases.

    *) Bugfix: a segmentation fault might occur in a worker
    process if the ngx_http_xslt_module was used.

    *) Bugfix: nginx could not be built on MacOSX in some
    cases.

    *) Bugfix: the 'limit_rate' directive with high rates
    might result in truncated responses on 32-bit platforms.

    *) Bugfix: a segmentation fault might occur in a worker
    process if the 'if' directive was used.

    *) Bugfix: a '100 Continue' response was issued with
    '413 Request Entity Too Large' responses.

    *) Bugfix: the 'image_filter',
    'image_filter_jpeg_quality' and 'image_filter_sharpen'
    directives might be inherited incorrectly.

    *) Bugfix: 'crypt_r() failed' errors might appear if the
    'auth_basic' directive was used on Linux.

    *) Bugfix: in backup servers handling.

    *) Bugfix: proxied HEAD requests might return incorrect
    response if the 'gzip' directive was used.

    *) Bugfix: a segmentation fault occurred on start or
    during reconfiguration if the 'keepalive' directive was
    specified more than once in a single upstream block.

    *) Bugfix: in the 'proxy_method' directive.

    *) Bugfix: a segmentation fault might occur in a worker
    process if resolver was used with the poll method.

    *) Bugfix: nginx might hog CPU during SSL handshake with
    a backend if the select, poll, or /dev/poll methods were
    used.

    *) Bugfix: the '[crit] SSL_write() failed (SSL:)' error.

    *) Bugfix: in the 'fastcgi_keep_conn' directive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821184"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nginx packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/24");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"nginx-1.2.9-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nginx-debuginfo-1.2.9-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nginx-debugsource-1.2.9-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx / nginx-debuginfo / nginx-debugsource");
}
