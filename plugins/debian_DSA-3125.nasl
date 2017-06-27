#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3125. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80446);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/22 14:14:58 $");

  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_bugtraq_id(71934, 71935, 71936, 71937, 71939, 71940, 71941, 71942);
  script_osvdb_id(116423, 116790, 116791, 116792, 116793, 116794, 116795, 116796);
  script_xref(name:"DSA", value:"3125");

  script_name(english:"Debian DSA-3125-1 : openssl - security update (FREAK)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit. The Common Vulnerabilities and Exposures
project identifies the following issues :

  - CVE-2014-3569
    Frank Schmirler reported that the ssl23_get_client_hello
    function in OpenSSL does not properly handle attempts to
    use unsupported protocols. When OpenSSL is built with
    the no-ssl3 option and a SSL v3 ClientHello is received,
    the ssl method would be set to NULL which could later
    result in a NULL pointer dereference and daemon crash.

  - CVE-2014-3570
    Pieter Wuille of Blockstream reported that the bignum
    squaring (BN_sqr) may produce incorrect results on some
    platforms, which might make it easier for remote
    attackers to defeat cryptographic protection mechanisms.

  - CVE-2014-3571
    Markus Stenberg of Cisco Systems, Inc. reported that a
    carefully crafted DTLS message can cause a segmentation
    fault in OpenSSL due to a NULL pointer dereference. A
    remote attacker could use this flaw to mount a denial of
    service attack.

  - CVE-2014-3572
    Karthikeyan Bhargavan of the PROSECCO team at INRIA
    reported that an OpenSSL client would accept a handshake
    using an ephemeral ECDH ciphersuite if the server key
    exchange message is omitted. This allows remote SSL
    servers to conduct ECDHE-to-ECDH downgrade attacks and
    trigger a loss of forward secrecy.

  - CVE-2014-8275
    Antti Karjalainen and Tuomo Untinen of the Codenomicon
    CROSS project and Konrad Kraszewski of Google reported
    various certificate fingerprint issues, which allow
    remote attackers to defeat a fingerprint-based
    certificate-blacklist protection mechanism.

  - CVE-2015-0204
    Karthikeyan Bhargavan of the PROSECCO team at INRIA
    reported that an OpenSSL client will accept the use of
    an ephemeral RSA key in a non-export RSA key exchange
    ciphersuite, violating the TLS standard. This allows
    remote SSL servers to downgrade the security of the
    session.

  - CVE-2015-0205
    Karthikeyan Bhargavan of the PROSECCO team at INRIA
    reported that an OpenSSL server will accept a DH
    certificate for client authentication without the
    certificate verify message. This flaw effectively allows
    a client to authenticate without the use of a private
    key via crafted TLS handshake protocol traffic to a
    server that recognizes a certification authority with DH
    support.

  - CVE-2015-0206
    Chris Mueller discovered a memory leak in the
    dtls1_buffer_record function. A remote attacker could
    exploit this flaw to mount a denial of service through
    memory exhaustion by repeatedly sending specially
    crafted DTLS records."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3125"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.0.1e-2+deb7u14.

For the upcoming stable distribution (jessie), these problems will be
fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/12");
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
if (deb_check(release:"7.0", prefix:"libssl-dev", reference:"1.0.1e-2+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libssl-doc", reference:"1.0.1e-2+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0", reference:"1.0.1e-2+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1e-2+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"openssl", reference:"1.0.1e-2+deb7u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
