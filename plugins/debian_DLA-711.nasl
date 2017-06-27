#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-711-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94941);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/18 14:29:49 $");

  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_osvdb_id(146565, 146567, 146568, 146569, 146570, 146571, 146572, 146573, 146574);

  script_name(english:"Debian DLA-711-1 : curl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-8615 If cookie state is written into a cookie jar file that
is later read back and used for subsequent requests, a malicious HTTP
server can inject new cookies for arbitrary domains into said cookie
jar. The issue pertains to the function that loads cookies into
memory, which reads the specified file into a fixed-size buffer in a
line-by-line manner using the `fgets()` function. If an invocation of
fgets() cannot read the whole line into the destination buffer due to
it being too small, it truncates the output. This way, a very long
cookie (name + value) sent by a malicious server would be stored in
the file and subsequently that cookie could be read partially and
crafted correctly, it could be treated as a different cookie for
another server.

CVE-2016-8616 When re-using a connection, curl was doing case
insensitive comparisons of user name and password with the existing
connections. This means that if an unused connection with proper
credentials exists for a protocol that has connection-scoped
credentials, an attacker can cause that connection to be reused if
s/he knows the case-insensitive version of the correct password.

CVE-2016-8617 In libcurl's base64 encode function, the output buffer
is allocated as follows without any checks on insize: malloc( insize *
4 / 3 + 4 ) On systems with 32-bit addresses in userspace (e.g. x86,
ARM, x32), the multiplication in the expression wraps around if insize
is at least 1GB of data. If this happens, an undersized output buffer
will be allocated, but the full result will be written, thus causing
the memory behind the output buffer to be overwritten. Systems with 64
bit versions of the `size_t` type are not affected by this issue.

CVE-2016-8618 The libcurl API function called `curl_maprintf()` can be
tricked into doing a double-free due to an unsafe `size_t`
multiplication, on systems using 32 bit `size_t` variables. The
function is also used internallty in numerous situations. Systems with
64 bit versions of the `size_t` type are not affected by this issue.

CVE-2016-8619 In curl's implementation of the Kerberos authentication
mechanism, the function `read_data()` in security.c is used to fill
the necessary krb5 structures. When reading one of the length fields
from the socket, it fails to ensure that the length parameter passed
to realloc() is not set to 0.

CVE-2016-8621 The `curl_getdate` converts a given date string into a
numerical timestamp and it supports a range of different formats and
possibilites to express a date and time. The underlying date parsing
function is also used internally when parsing for example HTTP cookies
(possibly received from remote servers) and it can be used when doing
conditional HTTP requests.

CVE-2016-8622 The URL percent-encoding decode function in libcurl is
called `curl_easy_unescape`. Internally, even if this function would
be made to allocate a unscape destination buffer larger than 2GB, it
would return that new length in a signed 32 bit integer variable, thus
the length would get either just truncated or both truncated and
turned negative. That could then lead to libcurl writing outside of
its heap based buffer.

CVE-2016-8623 libcurl explicitly allows users to share cookies between
multiple easy handles that are concurrently employed by different
threads. When cookies to be sent to a server are collected, the
matching function collects all cookies to send and the cookie lock is
released immediately afterwards. That funcion however only returns a
list with

*references* back to the original strings for name, value, path and so
on. Therefore, if another thread quickly takes the lock and frees one
of the original cookie structs together with its strings, a
use-after-free can occur and lead to information disclosure. Another
thread can also replace the contents of the cookies from separate HTTP
responses or API calls.

CVE-2016-8624 curl doesn't parse the authority component of the URL
correctly when the host name part ends with a '#' character, and could
instead be tricked into connecting to a different host. This may have
security implications if you for example use an URL parser that
follows the RFC to check for allowed domains before using curl to
request them.

For Debian 7 'Wheezy', these problems have been fixed in version
7.26.0-1+wheezy17.

We recommend that you upgrade your curl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/11/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/curl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"curl", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-dbg", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-gnutls", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-nss", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-gnutls-dev", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-nss-dev", reference:"7.26.0-1+wheezy17")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-openssl-dev", reference:"7.26.0-1+wheezy17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
