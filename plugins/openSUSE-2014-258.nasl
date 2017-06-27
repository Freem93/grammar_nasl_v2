#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-258.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75309);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-0133");

  script_name(english:"openSUSE Security Update : nginx (openSUSE-SU-2014:0450-1)");
  script_summary(english:"Check for the openSUSE-2014-258 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"nginx was updated to 1.4.7 to fix bugs and security issues.

Fixed security issues :

  - CVE-2014-0133: nginx:heap-based buffer overflow in SPDY
    implementation

New upstream release 1.4.7 (bnc#869076) (CVE-2014-0133)

*) Security: a heap memory buffer overflow might occur in a worker
process while handling a specially crafted request by
ngx_http_spdy_module, potentially resulting in arbitrary code
execution (CVE-2014-0133). Thanks to Lucas Molas, researcher at
Programa STIC, Fundaci&oacute;n Dr. Manuel Sadosky, Buenos Aires,
Argentina.

*) Bugfix: in the 'fastcgi_next_upstream' directive. Thanks
to Lucas Molas.

*) Bugfix: the 'client_max_body_size' directive might not
work when reading a request body using chunked transfer
encoding; the bug had appeared in 1.3.9. Thanks to Lucas
Molas.

*) Bugfix: a segmentation fault might occur in a worker
process when proxying WebSocket connections.

*) Bugfix: the $ssl_session_id variable contained full
session serialized instead of just a session id. Thanks to
Ivan Risti&#x107;.

*) Bugfix: client connections might be immediately closed if
deferred accept was used; the bug had appeared in 1.3.15.

*) Bugfix: alerts 'zero size buf in output' might appear in
logs while proxying; the bug had appeared in 1.3.9.

*) Bugfix: a segmentation fault might occur in a worker
process if the ngx_http_spdy_module was used.

*) Bugfix: proxied WebSocket connections might hang right
after handshake if the select, poll, or /dev/poll methods
were used.

*) Bugfix: a timeout might occur while reading client
request body in an SSL connection using chunked transfer
encoding.

*) Bugfix: memory leak in nginx/Windows."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869076"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nginx packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debugsource");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"nginx-1.4.7-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nginx-debuginfo-1.4.7-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nginx-debugsource-1.4.7-3.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}
