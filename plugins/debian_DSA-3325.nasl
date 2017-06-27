#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3325. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85164);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id("CVE-2015-3183", "CVE-2015-3185");
  script_osvdb_id(123122, 123123);
  script_xref(name:"DSA", value:"3325");

  script_name(english:"Debian DSA-3325-1 : apache2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

  - CVE-2015-3183
    An HTTP request smuggling attack was possible due to a
    bug in parsing of chunked requests. A malicious client
    could force the server to misinterpret the request
    length, allowing cache poisoning or credential hijacking
    if an intermediary proxy is in use.

  - CVE-2015-3185
    A design error in the 'ap_some_auth_required' function
    renders the API unusuable in apache2 2.4.x. This could
    lead to modules using this API to allow access when they
    should otherwise not do so. The fix backports the new
    'ap_some_authn_required' API from 2.4.16. This issue
    does not affect the oldstable distribution (wheezy).

In addition, the updated package for the oldstable distribution
(wheezy) removes a limitation of the Diffie-Hellman (DH) parameters to
1024 bits. This limitation may potentially allow an attacker with very
large computing resources, like a nation-state, to break DH key
exchange by precomputation. The updated apache2 package also allows to
configure custom DH parameters. More information is contained in the
changelog.Debian.gz file. These improvements were already present in
the stable, testing, and unstable distributions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3325"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2.2.22-13+deb7u5.

For the stable distribution (jessie), these problems have been fixed
in version 2.4.10-10+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");
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
if (deb_check(release:"7.0", prefix:"apache2", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-dbg", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-doc", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-event", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-itk", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-prefork", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-worker", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-prefork-dev", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec-custom", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-threaded-dev", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-utils", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-bin", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-common", reference:"2.2.22-13+deb7u5")) flag++;
if (deb_check(release:"8.0", prefix:"apache2", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-bin", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-data", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dbg", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dev", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-doc", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-event", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-itk", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-prefork", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-worker", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-custom", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-pristine", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-utils", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-bin", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-common", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-macro", reference:"2.4.10-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-html", reference:"2.4.10-10+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
