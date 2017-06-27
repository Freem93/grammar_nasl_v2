#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2390. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57543);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4354", "CVE-2011-4576", "CVE-2011-4619");
  script_bugtraq_id(50882, 51281);
  script_osvdb_id(77650, 78186, 78187, 78188, 78190);
  script_xref(name:"DSA", value:"2390");

  script_name(english:"Debian DSA-2390-1 : openssl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in OpenSSL, an implementation
of TLS and related protocols. The Common Vulnerabilities and Exposures
project identifies the following vulnerabilities :

  - CVE-2011-4108
    The DTLS implementation performs a MAC check only if
    certain padding is valid, which makes it easier for
    remote attackers to recover plaintext via a padding
    oracle attack.

  - CVE-2011-4109
    A double free vulnerability when
    X509_V_FLAG_POLICY_CHECK is enabled, allows remote
    attackers to cause applications crashes and potentially
    allow execution of arbitrary code by triggering failure
    of a policy check.

  - CVE-2011-4354
    On 32-bit systems, the operations on NIST elliptic
    curves P-256 and P-384 are not correctly implemented,
    potentially leaking the private ECC key of a TLS server.
    (Regular RSA-based keys are not affected by this
    vulnerability.)

  - CVE-2011-4576
    The SSL 3.0 implementation does not properly initialize
    data structures for block cipher padding, which might
    allow remote attackers to obtain sensitive information
    by decrypting the padding data sent by an SSL peer.

  - CVE-2011-4619
    The Server Gated Cryptography (SGC) implementation in
    OpenSSL does not properly handle handshake restarts,
    unnecessarily simplifying CPU exhaustion attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2390"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 0.9.8g-15+lenny15.

For the stable distribution (squeeze), these problems have been fixed
in version 0.9.8o-4squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny15")) flag++;
if (deb_check(release:"6.0", prefix:"libcrypto0.9.8-udeb", reference:"0.9.8o-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libssl-dev", reference:"0.9.8o-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8", reference:"0.9.8o-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8o-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"openssl", reference:"0.9.8o-4squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
