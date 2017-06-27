#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-885-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99202);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/12 14:39:07 $");

  script_cve_id("CVE-2017-7233", "CVE-2017-7234");
  script_osvdb_id(154910, 154911);

  script_name(english:"Debian DLA-885-1 : python-django security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there were two vulnerabilities in
python-django, a high-level Python web development framework.

CVE-2017-7233 (#859515): Open redirect and possible XSS attack via
user-supplied numeric redirect URLs. Django relies on user input in
some cases (e.g. django.contrib.auth.views.login() and i18n) to
redirect the user to an 'on success' URL. The security check for these
redirects (namely is_safe_url()) considered some numeric URLs (e.g.
http:999999999) 'safe' when they shouldn't be. Also, if a developer
relied on is_safe_url() to provide safe redirect targets and puts such
a URL into a link, they could suffer from an XSS attack.

CVE-2017-7234 (#895516): Open redirect vulnerability in
django.views.static.serve; A maliciously crafted URL to a Django site
using the serve() view could redirect to any other domain. The view no
longer does any redirects as they don't provide any known, useful
functionality.

For Debian 7 'Wheezy', this issue has been fixed in python-django
version 1.4.22-1+deb7u3.

We recommend that you upgrade your python-django packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-django"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected python-django, and python-django-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"python-django", reference:"1.4.22-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python-django-doc", reference:"1.4.22-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
