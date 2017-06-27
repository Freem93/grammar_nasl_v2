#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3287. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84170);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2014-8176", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-4000");
  script_osvdb_id(122331, 122875, 123172, 123173, 123174, 123175, 123176);
  script_xref(name:"DSA", value:"3287");

  script_name(english:"Debian DSA-3287-1 : openssl - security update (Logjam)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in OpenSSL, a Secure Sockets
Layer toolkit.

  - CVE-2014-8176
    Praveen Kariyanahalli, Ivan Fratric and Felix Groebert
    discovered that an invalid memory free could be
    triggered when buffering DTLS data. This could allow
    remote attackers to cause a denial of service (crash) or
    potentially execute arbitrary code. This issue only
    affected the oldstable distribution (wheezy).

  - CVE-2015-1788
    Joseph Barr-Pixton discovered that an infinite loop
    could be triggered due to incorrect handling of
    malformed ECParameters structures. This could allow
    remote attackers to cause a denial of service.

  - CVE-2015-1789
    Robert Swiecki and Hanno Bock discovered that the
    X509_cmp_time function could read a few bytes out of
    bounds. This could allow remote attackers to cause a
    denial of service (crash) via crafted certificates and
    CRLs.

  - CVE-2015-1790
    Michal Zalewski discovered that the PKCS#7 parsing code
    did not properly handle missing content which could lead
    to a NULL pointer dereference. This could allow remote
    attackers to cause a denial of service (crash) via
    crafted ASN.1-encoded PKCS#7 blobs.

  - CVE-2015-1791
    Emilia Kasper discovered that a race condition could
    occur due to incorrect handling of NewSessionTicket in a
    multi-threaded client, leading to a double free. This
    could allow remote attackers to cause a denial of
    service (crash).

  - CVE-2015-1792
    Johannes Bauer discovered that the CMS code could enter
    an infinite loop when verifying a signedData message, if
    presented with an unknown hash function OID. This could
    allow remote attackers to cause a denial of service.

Additionally OpenSSL will now reject handshakes using DH parameters
shorter than 768 bits as a countermeasure against the Logjam attack
(CVE-2015-4000 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3287"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.0.1e-2+deb7u17.

For the stable distribution (jessie), these problems have been fixed
in version 1.0.1k-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");
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
if (deb_check(release:"7.0", prefix:"libssl-dev", reference:"1.0.1e-2+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"libssl-doc", reference:"1.0.1e-2+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0", reference:"1.0.1e-2+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1e-2+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"openssl", reference:"1.0.1e-2+deb7u17")) flag++;
if (deb_check(release:"8.0", prefix:"libcrypto1.0.0-udeb", reference:"1.0.1k-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-dev", reference:"1.0.1k-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-doc", reference:"1.0.1k-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0", reference:"1.0.1k-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1k-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openssl", reference:"1.0.1k-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
