#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96037);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-5387", "CVE-2016-8740", "CVE-2016-8743");
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"FreeBSD : Apache httpd -- several vulnerabilities (862d6ab3-c75e-11e6-9f98-20cf30e32f6d) (httpoxy)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache Software Foundation reports :

- Important: Apache HTTP Request Parsing Whitespace Defects
CVE-2016-8743 Apache HTTP Server, prior to release 2.4.25, accepted a
broad pattern of unusual whitespace patterns from the user-agent,
including bare CR, FF, VTAB in parsing the request line and request
header lines, as well as HTAB in parsing the request line. Any bare CR
present in request lines was treated as whitespace and remained in the
request field member 'the_request', while a bare CR in the request
header field name would be honored as whitespace, and a bare CR in the
request header field value was retained the input headers array.
Implied additional whitespace was accepted in the request line and
prior to the ':' delimiter of any request header lines. RFC7230
Section 3.5 calls out some of these whitespace exceptions, and section
3.2.3 eliminated and clarified the role of implied whitespace in the
grammer of this specification. Section 3.1.1 requires exactly one
single SP between the method and request-target, and between the
request-target and HTTP-version, followed immediately by a CRLF
sequence. None of these fields permit any (unencoded) CTL character
whatsoever. Section 3.2.4 explicitly disallowed any whitespace from
the request header field prior to the ':' character, while Section 3.2
disallows all CTL characters in the request header line other than the
HTAB character as whitespace. These defects represent a security
concern when httpd is participating in any chain of proxies or
interacting with back-end application servers, either through
mod_proxy or using conventional CGI mechanisms. In each case where one
agent accepts such CTL characters and does not treat them as
whitespace, there is the possiblity in a proxy chain of generating two
responses from a server behind the uncautious proxy agent. In a
sequence of two requests, this results in request A to the first proxy
being interpreted as requests A + A' by the backend server, and if
requests A and B were submitted to the first proxy in a keepalive
connection, the proxy may interpret response A' as the response to
request B, polluting the cache or potentially serving the A' content
to a different downstream user-agent. These defects are addressed with
the release of Apache HTTP Server 2.4.25 and coordinated by a new
directive HttpProtocolOptions Strict

- low: DoS vulnerability in mod_auth_digest CVE-2016-2161 Malicious
input to mod_auth_digest will cause the server to crash, and each
instance continues to crash even for subsequently valid requests.

- low: Padding Oracle in Apache mod_session_crypto CVE-2016-0736
Authenticate the session data/cookie presented to mod_session_crypto
with a MAC (SipHash) to prevent deciphering or tampering with a
padding oracle attack.

- low: Padding Oracle in Apache mod_session_crypto CVE-2016-0736
Authenticate the session data/cookie presented to mod_session_crypto
with a MAC (SipHash) to prevent deciphering or tampering with a
padding oracle attack.

- low: HTTP/2 CONTINUATION denial of service CVE-2016-8740 The HTTP/2
protocol implementation (mod_http2) had an incomplete handling of the
LimitRequestFields directive. This allowed an attacker to inject
unlimited request headers into the server, leading to eventual memory
exhaustion.

- n/a: HTTP_PROXY environment variable 'httpoxy' mitigation
CVE-2016-5387 HTTP_PROXY is a well-defined environment variable in a
CGI process, which collided with a number of libraries which failed to
avoid colliding with this CGI namespace. A mitigation is provided for
the httpd CGI environment to avoid populating the 'HTTP_PROXY'
variable from a 'Proxy:' header, which has never been registered by
IANA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://httpd.apache.org/security/vulnerabilities_24.html"
  );
  # http://www.freebsd.org/ports/portaudit/862d6ab3-c75e-11e6-9f98-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae7da426"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"apache24<2.4.25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
