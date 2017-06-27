#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3085. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79696);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2014-9031", "CVE-2014-9033", "CVE-2014-9034", "CVE-2014-9035", "CVE-2014-9036", "CVE-2014-9037", "CVE-2014-9038", "CVE-2014-9039");
  script_bugtraq_id(71231, 71232, 71233, 71234, 71236, 71237, 71238);
  script_osvdb_id(114861);
  script_xref(name:"DSA", value:"3085");

  script_name(english:"Debian DSA-3085-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in Wordpress, a web
blogging tool, resulting in denial of service or information
disclosure. More information can be found in the upstream advisory at

  - CVE-2014-9031
    Jouko Pynnonen discovered an unauthenticated cross site
    scripting vulnerability (XSS) in wptexturize(),
    exploitable via comments or posts.

  - CVE-2014-9033
    Cross site request forgery (CSRF) vulnerability in the
    password changing process, which could be used by an
    attacker to trick an user into changing her password.

  - CVE-2014-9034
    Javier Nieto Arevalo and Andres Rojas Guerrero reported
    a potential denial of service in the way the phpass
    library is used to handle passwords, since no maximum
    password length was set.

  - CVE-2014-9035
    John Blackbourn reported an XSS in the 'Press This'
    function (used for quick publishing using a browser
    'bookmarklet').

  - CVE-2014-9036
    Robert Chapin reported an XSS in the HTML filtering of
    CSS in posts.

  - CVE-2014-9037
    David Anderson reported a hash comparison vulnerability
    for passwords stored using the old-style MD5 scheme.
    While unlikely, this could be exploited to compromise an
    account, if the user had not logged in after a Wordpress
    2.5 update (uploaded to Debian on 2 Apr, 2008) and the
    password MD5 hash could be collided with due to PHP
    dynamic comparison.

  - CVE-2014-9038
    Ben Bidner reported a server side request forgery (SSRF)
    in the core HTTP layer which unsufficiently blocked the
    loopback IP address space.

  - CVE-2014-9039
    Momen Bassel, Tanoy Bose, and Bojan Slavkovic reported a
    vulnerability in the password reset process: an email
    address change would not invalidate a previous password
    reset email."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=770425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3085"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.6.1+dfsg-1~deb7u5.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 4.0.1+dfsg-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
