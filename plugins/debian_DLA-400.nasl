#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-400-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88107);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/12/27 14:30:00 $");

  script_cve_id("CVE-2009-3555", "CVE-2011-3389", "CVE-2012-4929", "CVE-2014-3566");
  script_bugtraq_id(36935, 49388, 49778, 55704, 70574);
  script_osvdb_id(59968, 59969, 59970, 59971, 59972, 59973, 59974, 60366, 60521, 61234, 61718, 61784, 61785, 61929, 62064, 62135, 62210, 62273, 62536, 62877, 64040, 64499, 64725, 65202, 66315, 67029, 69032, 69561, 70055, 70620, 71951, 71961, 74335, 74829, 75622, 77832, 85927, 90597, 99240, 100172, 104575, 104796, 113251, 120248, 122533, 143349, 149086);

  script_name(english:"Debian DLA-400-1 : pound security update (BEAST) (POODLE)");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes certain known vulnerabilities in pound in
squeeze-lts by backporting the version in wheezy.

CVE-2009-3555 The TLS protocol, and the SSL protocol 3.0 and possibly
earlier, as used in Microsoft Internet Information Services (IIS) 7.0,
mod_ssl in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before
0.9.8l, GnuTLS 2.8.5 and earlier, Mozilla Network Security Services
(NSS) 3.12.4 and earlier, multiple Cisco products, and other products,
does not properly associate renegotiation handshakes with an existing
connection, which allows man-in-the-middle attackers to insert data
into HTTPS sessions, and possibly other types of sessions protected by
TLS or SSL, by sending an unauthenticated request that is processed
retroactively by a server in a post-renegotiation context, related to
a 'plaintext injection' attack, aka the 'Project Mogul' issue.

CVE-2011-3389 The SSL protocol, as used in certain configurations in
Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox,
Google Chrome, Opera, and other products, encrypts data by using CBC
mode with chained initialization vectors, which allows
man-in-the-middle attackers to obtain plaintext HTTP headers via a
blockwise chosen-boundary attack (BCBA) on an HTTPS session, in
conjunction with JavaScript code that uses (1) the HTML5 WebSocket
API, (2) the Java URLConnection API, or (3) the Silverlight WebClient
API, aka a 'BEAST' attack.

CVE-2012-4929 The TLS protocol 1.2 and earlier, as used in Mozilla
Firefox, Google Chrome, Qt, and other products, can encrypt compressed
data without properly obfuscating the length of the unencrypted data,
which allows man-in-the-middle attackers to obtain plaintext HTTP
headers by observing length differences during a series of guesses in
which a string in an HTTP request potentially matches an unknown
string in an HTTP header, aka a 'CRIME' attack.

CVE-2014-3566 The SSL protocol 3.0, as used in OpenSSL through 1.0.1i
and other products, uses nondeterministic CBC padding, which makes it
easier for man-in-the-middle attackers to obtain cleartext data via a
padding-oracle attack, aka the 'POODLE' issue.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/01/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/pound"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected pound package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"pound", reference:"2.6-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
