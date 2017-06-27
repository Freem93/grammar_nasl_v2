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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56187);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/22 00:10:43 $");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (d01d10c7-de2d-11e0-b215-00215c6a37bb)");
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
"The Django project reports :

Today the Django team is issuing multiple releases -- Django 1.2.6 and
Django 1.3.1 -- to remedy security issues reported to us.
Additionally, this announcement contains advisories for several other
issues which, while not requiring changes to Django itself, will be of
concern to users of Django.

All users are encouraged to upgrade Django, and to implement the
recommendations in these advisories, immediately. Session manipulation
Django's session framework, django.contrib.sessions, is configurable
to use any of multiple backends for storage of session data. One such
backend, provided with Django itself, integrates with Django's cache
framework to use the cache as storage for session data.

When configured in this fashion using memory-based sessions and
caching, Django sessions are stored directly in the root namespace of
the cache, using session identifiers as keys.

This results in a potential attack when coupled with an application
storing user-supplied data in the cache; if an attacker can cause data
to be cached using a key which is also a valid session identifier,
Django's session framework will treat that data -- so long as it is a
dictionary-like object -- as the session, thus allowing arbitrary data
to be inserted into a session so long as the attacker knows the
session key. Denial of service attack via URLField Django's model
system includes a field type -- URLField -- which validates that the
supplied value is a valid URL, and if the boolean keyword argument
verify_exists is true, attempts to validate that the supplied URL also
resolves, by issuing a request to it.

By default, the underlying socket libraries in Python do not have a
timeout. This can manifest as a security problem in three different
ways :

- An attacker can supply a slow-to-respond URL. Each request will tie
up a server process for a period of time; if the attacker is able to
make enough requests, they can tie up all available server processes.

- An attacker can supply a URL under his or her control, and which
will simply hold an open connection indefinitely. Due to the lack of
timeout, the Django process attempting to verify the URL will
similarly spin indefinitely. Repeating this can easily tie up all
available server processes.

- An attacker can supply a URL under his or her control which not only
keeps the connection open, but also sends an unending stream of random
garbage data. This data will cause the memory usage of the Django
process (which will hold the response in memory) to grow without
bound, thus consuming not only server processes but also server
memory. URLField redirection The regular expression which validates
URLs is used to check the supplied URL before issuing a check to
verify that it exists, but if that URL issues a redirect in response
to the request, no validation of the resulting redirected URL is
performed, including basic checks for supported protocols (HTTP,
HTTPS, and FTP).

This creates a small window for an attacker to gain knowledge of, for
example, server layout; a redirect to a file:// URL, for example, will
tell an attacker whether a given file exists locally on the server.

Additionally, although the initial request issued by Django uses the
HEAD method for HTTP/HTTPS, the request to the target of the redirect
is issued using GET. This may create further issues for systems which
implicitly trust GET requests from the local machine/network. Host
header cache poisoning In several places, Django itself -- independent
of the developer -- generates full URLs (for example, when issuing
HTTP redirects). Currently this uses the value of the HTTP Host header
from the request to construct the URL, which opens a potential
cache-poisoning vector: an attacker can submit a request with a Host
header of his or her choice, receive a response which constructs URLs
using that Host header, and -- if that response is cached -- further
requests will be served out of cache using URLs containing the
attacker's host of choice."
  );
  # https://www.djangoproject.com/weblog/2011/sep/09/security-releases-issued/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?938ac84a"
  );
  # http://www.freebsd.org/ports/portaudit/d01d10c7-de2d-11e0-b215-00215c6a37bb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58da18ad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"py23-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>=1.3<1.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>=1.2<1.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django-devel<16758,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django-devel<16758,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django-devel<16758,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django-devel<16758,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django-devel<16758,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django-devel<16758,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django-devel<16758,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
