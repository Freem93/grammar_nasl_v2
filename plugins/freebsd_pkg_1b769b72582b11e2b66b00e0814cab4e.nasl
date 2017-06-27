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
  script_id(63396);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/21 23:43:36 $");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (1b769b72-582b-11e2-b66b-00e0814cab4e)");
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

Several earlier Django security releases focused on the issue of
poisoning the HTTP Host header, causing Django to generate URLs
pointing to arbitrary, potentially-malicious domains.

In response to further input received and reports of continuing issues
following the previous release, we're taking additional steps to
tighten Host header validation. Rather than attempt to accommodate all
features HTTP supports here, Django's Host header validation attempts
to support a smaller, but far more common, subset :

- Hostnames must consist of characters [A-Za-z0-9] plus hyphen ('-')
or dot ('.').

- IP addresses -- both IPv4 and IPv6 -- are permitted.

- Port, if specified, is numeric.

Any deviation from this will now be rejected, raising the exception
django.core.exceptions.SuspiciousOperation.

- Redirect poisoning

Also following up on a previous issue: in July of this year, we made
changes to Django's HTTP redirect classes, performing additional
validation of the scheme of the URL to redirect to (since, both within
Django's own supplied applications and many third-party applications,
accepting a user-supplied redirect target is a common pattern).

Since then, two independent audits of the code turned up further
potential problems. So, similar to the Host-header issue, we are
taking steps to provide tighter validation in response to reported
problems (primarily with third-party applications, but to a certain
extent also within Django itself). This comes in two parts :

- A new utility function, django.utils.http.is_safe_url, is added;
this function takes a URL and a hostname, and checks that the URL is
either relative, or if absolute matches the supplied hostname. This
function is intended for use whenever user-supplied redirect targets
are accepted, to ensure that such redirects cannot lead to arbitrary
third-party sites.

- All of Django's own built-in views -- primarily in the
authentication system -- which allow user-supplied redirect targets
now use is_safe_url to validate the supplied URL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2012/dec/10/security/"
  );
  # http://www.freebsd.org/ports/portaudit/1b769b72-582b-11e2-b66b-00e0814cab4e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de167fa5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:django13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"django<1.4.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"django13<1.3.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
