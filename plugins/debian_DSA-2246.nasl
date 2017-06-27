#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2246. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55034);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-1402", "CVE-2011-1403", "CVE-2011-1404", "CVE-2011-1405", "CVE-2011-1406");
  script_bugtraq_id(47798);
  script_osvdb_id(73454, 73455, 73456, 73457, 73458);
  script_xref(name:"DSA", value:"2246");

  script_name(english:"Debian DSA-2246-1 : mahara - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Mahara, an electronic
portfolio, weblog, and resume builder. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2011-1402
    It was discovered that previous versions of Mahara did
    not check user credentials before adding a secret URL to
    a view or suspending a user.

  - CVE-2011-1403
    Due to a misconfiguration of the Pieform package in
    Mahara, the cross-site request forgery protection
    mechanism that Mahara relies on to harden its form was
    not working and was essentially disabled. This is a
    critical vulnerability which could allow attackers to
    trick other users (for example administrators) into
    performing malicious actions on behalf of the attacker.
    Most Mahara forms are vulnerable.

  - CVE-2011-1404
    Many of the JSON structures returned by Mahara for its
    AJAX interactions included more information than what
    ought to be disclosed to the logged in user. New
    versions of Mahara limit this information to what is
    necessary for each page.

  - CVE-2011-1405
    Previous versions of Mahara did not escape the contents
    of HTML emails sent to users. Depending on the filters
    enabled in one's mail reader, it could lead to
    cross-site scripting attacks.

  - CVE-2011-1406
    It has been pointed out to us that if Mahara is
    configured (through its wwwroot variable) to use HTTPS,
    it will happily let users login via the HTTP version of
    the site if the web server is configured to serve
    content over both protocol. The new version of Mahara
    will, when the wwwroot points to an HTTPS URL,
    automatically redirect to HTTPS if it detects that it is
    being run over HTTP.

  We recommend that sites wanting to run Mahara over HTTPS make sure
  that their web server configuration does not allow the serving of
  content over HTTP and merely redirects to the secure version. We
  also suggest that site administrators consider adding the HSTS
  headers to their web server configuration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mahara"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2246"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mahara packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 1.0.4-4+lenny10.

For the stable distribution (squeeze), these problems have been fixed
in version 1.2.6-2+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mahara");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mahara", reference:"1.0.4-4+lenny10")) flag++;
if (deb_check(release:"6.0", prefix:"mahara", reference:"1.2.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-apache2", reference:"1.2.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-mediaplayer", reference:"1.2.6-2+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
