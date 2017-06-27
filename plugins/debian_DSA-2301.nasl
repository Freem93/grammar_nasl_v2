#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2301. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56074);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2009-4214", "CVE-2011-2930", "CVE-2011-2931", "CVE-2011-3186");
  script_bugtraq_id(37142, 49179);
  script_osvdb_id(60544, 74614, 74616, 74617);
  script_xref(name:"DSA", value:"2301");

  script_name(english:"Debian DSA-2301-2 : rails - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Rails, the Ruby web
application framework. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-4214
    A cross-site scripting (XSS) vulnerability had been
    found in the strip_tags function. An attacker may inject
    non-printable characters that certain browsers will then
    evaluate. This vulnerability only affects the oldstable
    distribution (lenny).

  - CVE-2011-2930
    A SQL injection vulnerability had been found in the
    quote_table_name method that could allow malicious users
    to inject arbitrary SQL into a query.

  - CVE-2011-2931
    A cross-site scripting (XSS) vulnerability had been
    found in the strip_tags helper. An parsing error can be
    exploited by an attacker, who can confuse the parser and
    may inject HTML tags into the output document.

  - CVE-2011-3186
    A newline (CRLF) injection vulnerability had been found
    in response.rb. This vulnerability allows an attacker to
    inject arbitrary HTTP headers and conduct HTTP response
    splitting attacks via the Content-Type header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/rails"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2301"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rails packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.1.0-7+lenny2.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"rails", reference:"2.1.0-7+lenny2")) flag++;
if (deb_check(release:"6.0", prefix:"libactionmailer-ruby", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactionmailer-ruby1.8", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactionpack-ruby", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactionpack-ruby1.8", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby1.8", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby1.9.1", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactiveresource-ruby", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactiveresource-ruby1.8", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby1.8", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby1.9.1", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rails", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rails-doc", reference:"2.3.5-1.2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rails-ruby1.8", reference:"2.3.5-1.2+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
