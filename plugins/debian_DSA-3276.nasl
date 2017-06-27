#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3276. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83919);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/04 13:39:49 $");

  script_cve_id("CVE-2015-4050");
  script_xref(name:"DSA", value:"3276");

  script_name(english:"Debian DSA-3276-1 : symfony - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jakub Zalas discovered that Symfony, a framework to create websites
and web applications, was vulnerable to restriction bypass. It was
affecting applications with ESI or SSI support enabled, that use the
FragmentListener. A malicious user could call any controller via the
/_fragment path by providing an invalid hash in the URL (or removing
it), bypassing URL signing and security rules."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/symfony"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3276"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the symfony packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.3.21+dfsg-4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:symfony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"php-symfony-browser-kit", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-class-loader", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-classloader", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-config", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-console", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-css-selector", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-debug", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dependency-injection", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-doctrine-bridge", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dom-crawler", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-event-dispatcher", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-eventdispatcher", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-filesystem", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-finder", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-form", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-framework-bundle", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-foundation", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-kernel", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-intl", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-locale", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-monolog-bridge", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-options-resolver", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-process", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-propel1-bridge", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-property-access", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-proxy-manager-bridge", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-routing", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security-bundle", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-serializer", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-stopwatch", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-swiftmailer-bridge", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-templating", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-translation", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bridge", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bundle", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-validator", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-web-profiler-bundle", reference:"2.3.21+dfsg-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-yaml", reference:"2.3.21+dfsg-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
