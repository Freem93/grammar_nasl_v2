#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(83842);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/27 16:10:33 $");

  script_cve_id("CVE-2014-3143", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3148");

  script_name(english:"FreeBSD : cURL -- multiple vulnerabilities (6294f75f-03f2-11e5-aab1-d050996490d0)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cURL reports :

libcurl keeps a pool of its last few connections around after use to
fascilitate easy, conventient and completely transparent connection
re-use for applications.

When doing HTTP requests NTLM authenticated, the entire connnection
becomes authenticated and not just the specific HTTP request which is
otherwise how HTTP works. This makes NTLM special and a subject for
special treatment in the code. With NTLM, once the connection is
authenticated, no further authentication is necessary until the
connection gets closed.

When doing HTTP requests Negotiate authenticated, the entire
connnection may become authenticated and not just the specific HTTP
request which is otherwise how HTTP works, as Negotiate can basically
use NTLM under the hood. curl was not adhering to this fact but would
assume that such requests would also be authenticated per request.

libcurl supports HTTP 'cookies' as documented in RFC 6265. Together
with each individual cookie there are several different properties,
but for this vulnerability we focus on the associated 'path' element.
It tells information about for which path on a given host the cookies
is valid.

The internal libcurl function called sanitize_cookie_path() that
cleans up the path element as given to it from a remote site or when
read from a file, did not properly validate the input. If given a path
that consisted of a single double-quote, libcurl would index a newly
allocated memory area with index -1 and assign a zero to it, thus
destroying heap memory it wasn't supposed to.

There is a private function in libcurl called fix_hostname() that
removes a trailing dot from the host name if there is one. The
function is called after the host name has been extracted from the URL
libcurl has been told to act on.

If a URL is given with a zero-length host name, like in 'http://:80'
or just ':80', fix_hostname() will index the host name pointer with a
-1 offset (as it blindly assumes a non-zero length) and both read and
assign that address."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20150422A.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20150422B.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20150422C.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20150422D.html"
  );
  # http://www.freebsd.org/ports/portaudit/6294f75f-03f2-11e5-aab1-d050996490d0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56033441"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"curl<7.42.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
