#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(62705);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:57:16 $");

  script_cve_id("CVE-2012-4520");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (5f326d75-1db9-11e2-bc8f-d0df9acfd7e5)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Django Project reports :

- Host header poisoning

Some parts of Django -- independent of end-user-written applications
-- make use of full URLs, including domain name, which are generated
from the HTTP Host header. Some attacks against this are beyond
Django's ability to control, and require the web server to be properly
configured; Django's documentation has for some time contained notes
advising users on such configuration.

Django's own built-in parsing of the Host header is, however, still
vulnerable, as was reported to us recently. The Host header parsing in
Django 1.3 and Django 1.4 -- specifically,
django.http.HttpRequest.get_host() -- was incorrectly handling
username/password information in the header. Thus, for example, the
following Host header would be accepted by Django when running on
'validsite.com' :

Host: validsite.com:random@evilsite.com

Using this, an attacker can cause parts of Django -- particularly the
password-reset mechanism -- to generate and display arbitrary URLs to
users.

To remedy this, the parsing in HttpRequest.get_host() is being
modified; Host headers which contain potentially dangerous content
(such as username/password pairs) now raise the exception
django.core.exceptions.SuspiciousOperation.

- Documentation of HttpOnly cookie option

As of Django 1.4, session cookies are always sent with the HttpOnly
flag, which provides some additional protection from cross-site
scripting attacks by denying client-side scripts access to the session
cookie.

Though not directly a security issue in Django, it has been reported
that the Django 1.4 documentation incorrectly described this change,
by claiming that this was now the default for all cookies set by the
HttpResponse.set_cookie() method.

The Django documentation has been updated to reflect that this only
applies to the session cookie. Users of Django are encouraged to
review their use of set_cookie() to ensure that the HttpOnly flag is
being set or unset appropriately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2012/oct/17/security/"
  );
  # http://www.freebsd.org/ports/portaudit/5f326d75-1db9-11e2-bc8f-d0df9acfd7e5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e743071"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:django13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"django<1.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"django13<1.3.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
