#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-715.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91618);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-2105", "CVE-2016-2107");

  script_name(english:"openSUSE Security Update : nodejs (openSUSE-2016-715)");
  script_summary(english:"Check for the openSUSE-2016-715 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs to version 4.4.5 fixes the several issues.

These security issues introduced by the bundled openssl were fixed by
going to version 1.0.2h :

  - CVE-2016-2107: The AES-NI implementation in OpenSSL did
    not consider memory allocation during a certain padding
    check, which allowed remote attackers to obtain
    sensitive cleartext information via a padding-oracle
    attack against an AES CBC session (bsc#977616).

  - CVE-2016-2105: Integer overflow in the EVP_EncodeUpdate
    function in crypto/evp/encode.c in OpenSSL allowed
    remote attackers to cause a denial of service (heap
    memory corruption) via a large amount of binary data
    (bsc#977614).

  - CVE-2016-0705: Double free vulnerability in the
    dsa_priv_decode function in crypto/dsa/dsa_ameth.c in
    OpenSSL allowed remote attackers to cause a denial of
    service (memory corruption) or possibly have unspecified
    other impact via a malformed DSA private key
    (bsc#968047).

  - CVE-2016-0797: Multiple integer overflows in OpenSSL
    allowed remote attackers to cause a denial of service
    (heap memory corruption or NULL pointer dereference) or
    possibly have unspecified other impact via a long digit
    string that is mishandled by the (1) BN_dec2bn or (2)
    BN_hex2bn function, related to crypto/bn/bn.h and
    crypto/bn/bn_print.c (bsc#968048).

  - CVE-2016-0702: The MOD_EXP_CTIME_COPY_FROM_PREBUF
    function in crypto/bn/bn_exp.c in OpenSSL did not
    properly consider cache-bank access times during modular
    exponentiation, which made it easier for local users to
    discover RSA keys by running a crafted application on
    the same Intel Sandy Bridge CPU core as a victim and
    leveraging cache-bank conflicts, aka a 'CacheBleed'
    attack (bsc#968050).

These non-security issues were fixed :

  - Fix faulty 'if' condition (string cannot equal a
    boolean).

  - buffer: Buffer no longer errors if you call lastIndexOf
    with a search term longer than the buffer.

  - contextify: Context objects are now properly garbage
    collected, this solves a problem some individuals were
    experiencing with extreme memory growth.

  - Update npm to 2.15.5.

- http: Invalid status codes can no longer be sent. Limited to 3 digit numbers between 100 - 999.

  - deps: Fix --gdbjit for embedders. Backported from v8
    upstream.

  - querystring: Restore throw when attempting to stringify
    bad surrogate pair.

- https: Under certain conditions SSL sockets may have been causing a memory leak when keepalive is enabled. This is no longer the case.

  - lib: The way that we were internally passing arguments
    was causing a potential leak. By copying the arguments
    into an array we can avoid this.

  - repl: Previously if you were using the repl in strict
    mode the column number would be wrong in a stack trace.
    This is no longer an issue.

  - deps: An update to v8 that introduces a new flag
    --perf_basic_prof_only_functions.

- http: A new feature in http(s) agent that catches errors on keep alived connections.

  - src: Better support for big-endian systems.

  - tls: A new feature that allows you to pass common SSL
    options to tls.createSecurePair.

  - build: Support python path that includes spaces.

- https: A potential fix for #3692
  (HTTP/HTTPS client requests throwing EPROTO).

  - installer: More readable profiling information from
    isolate tick logs.

  - process: Add support for symbols in event emitters
    (symbols didn't exist when it was written).

  - querystring: querystring.parse() is now 13-22% faster!

  - streams: Performance improvements for moving small
    buffers that shows a 5% throughput gain. IoT projects
    have been seen to be as much as 10% faster with this
    change!"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"nodejs-4.4.5-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debuginfo-4.4.5-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debugsource-4.4.5-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-devel-4.4.5-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-4.4.5-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debuginfo-4.4.5-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debugsource-4.4.5-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-devel-4.4.5-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"npm-4.4.5-27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / npm");
}
