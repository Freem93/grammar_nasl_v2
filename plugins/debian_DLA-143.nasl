#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-143-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82126);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0221");
  script_bugtraq_id(72078, 72079, 72081);
  script_osvdb_id(117065, 117066, 117067);

  script_name(english:"Debian DLA-143-1 : python-django security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Django:
https://www.djangoproject.com/weblog/2015/jan/13/security/

For Debian 6 Squeeeze, they have been fixed in version
1.2.3-3+squeeze12 of python-django. Here is what the upstream
developers have to say about those issues :

CVE-2015-0219 - WSGI header spoofing via underscore/dash conflation

When HTTP headers are placed into the WSGI environ, they are
normalized by converting to uppercase, converting all dashes to
underscores, and prepending HTTP_. For instance, a header X-Auth-User
would become HTTP_X_AUTH_USER in the WSGI environ (and thus also in
Django's request.META dictionary).

Unfortunately, this means that the WSGI environ cannot
distinguish between headers containing dashes and headers
containing underscores: X-Auth-User and X-Auth_User both
become HTTP_X_AUTH_USER. This means that if a header is used
in a security-sensitive way (for instance, passing
authentication information along from a front-end proxy),
even if the proxy carefully strips any incoming value for
X-Auth-User, an attacker may be able to provide an
X-Auth_User header (with underscore) and bypass this
protection.

In order to prevent such attacks, both Nginx and Apache 2.4+
strip all headers containing underscores from incoming
requests by default. Django's built-in development server
now does the same. Django's development server is not
recommended for production use, but matching the behavior of
common production servers reduces the surface area for
behavior changes during deployment.

CVE-2015-0220 - Possible XSS attack via user-supplied redirect URLs

Django relies on user input in some cases (e.g.
django.contrib.auth.views.login() and i18n) to redirect the user to an
'on success' URL. The security checks for these redirects (namely
django.util.http.is_safe_url()) didn't strip leading whitespace on the
tested URL and as such considered URLs like '\njavascript:...' safe.
If a developer relied on is_safe_url() to provide safe redirect
targets and put such a URL into a link, they could suffer from a XSS
attack. This bug doesn't affect Django currently, since we only put
this URL into the Location response header and browsers seem to ignore
JavaScript there.

CVE-2015-0221 - denial of service attack against
django.views.static.serve

In older versions of Django, the django.views.static.serve() view read
the files it served one line at a time. Therefore, a big file with no
newlines would result in memory usage equal to the size of that file.
An attacker could exploit this and launch a denial of service attack
by simultaneously requesting many large files. This view now reads the
file in chunks to prevent large memory usage.

Note, however, that this view has always carried a warning
that it is not hardened for production use and should be
used only as a development aid. Now may be a good time to
audit your project and serve your files in production using
a real front-end web server if you are not doing so.

Note that the version of Django in use in Debian 6 Squeeze was not
affected by CVE-2015-0222 (Database denial of service with
ModelMultipleChoiceField) since that feature does not exist in this
version.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/01/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2015/jan/13/security/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected python-django, and python-django-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"python-django", reference:"1.2.3-3+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"python-django-doc", reference:"1.2.3-3+squeeze12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
