#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3402. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87057);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-8124", "CVE-2015-8125");
  script_osvdb_id(130573, 130574);
  script_xref(name:"DSA", value:"3402");

  script_name(english:"Debian DSA-3402-1 : symfony - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in symfony, a framework
to create websites and web applications. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2015-8124
    The RedTeam Pentesting GmbH team discovered a session
    fixation vulnerability within the 'Remember Me' login
    feature, allowing an attacker to impersonate the victim
    towards the web application if the session id value was
    previously known to the attacker.

  - CVE-2015-8125
    Several potential remote timing attack vulnerabilities
    were discovered in classes from the Symfony Security
    component and in the legacy CSRF implementation from the
    Symfony Form component."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/symfony"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3402"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the symfony packages.

For the stable distribution (jessie), these problems have been fixed
in version 2.3.21+dfsg-4+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:symfony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/25");
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
if (deb_check(release:"8.0", prefix:"php-symfony-browser-kit", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-class-loader", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-classloader", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-config", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-console", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-css-selector", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-debug", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dependency-injection", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-doctrine-bridge", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-dom-crawler", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-event-dispatcher", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-eventdispatcher", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-filesystem", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-finder", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-form", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-framework-bundle", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-foundation", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-http-kernel", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-intl", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-locale", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-monolog-bridge", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-options-resolver", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-process", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-propel1-bridge", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-property-access", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-proxy-manager-bridge", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-routing", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-security-bundle", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-serializer", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-stopwatch", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-swiftmailer-bridge", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-templating", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-translation", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bridge", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-twig-bundle", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-validator", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-web-profiler-bundle", reference:"2.3.21+dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"php-symfony-yaml", reference:"2.3.21+dfsg-4+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
