#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3566. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90896);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109");
  script_osvdb_id(137577, 137896, 137897, 137898, 137899, 137900);
  script_xref(name:"DSA", value:"3566");

  script_name(english:"Debian DSA-3566-1 : openssl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in OpenSSL, a Secure Socket
Layer toolkit.

  - CVE-2016-2105
    Guido Vranken discovered that an overflow can occur in
    the function EVP_EncodeUpdate(), used for Base64
    encoding, if an attacker can supply a large amount of
    data. This could lead to a heap corruption.

  - CVE-2016-2106
    Guido Vranken discovered that an overflow can occur in
    the function EVP_EncryptUpdate() if an attacker can
    supply a large amount of data. This could lead to a heap
    corruption.

  - CVE-2016-2107
    Juraj Somorovsky discovered a padding oracle in the AES
    CBC cipher implementation based on the AES-NI
    instruction set. This could allow an attacker to decrypt
    TLS traffic encrypted with one of the cipher suites
    based on AES CBC.

  - CVE-2016-2108
    David Benjamin from Google discovered that two separate
    bugs in the ASN.1 encoder, related to handling of
    negative zero integer values and large universal tags,
    could lead to an out-of-bounds write.

  - CVE-2016-2109
    Brian Carpenter discovered that when ASN.1 data is read
    from a BIO using functions such as d2i_CMS_bio(), a
    short invalid encoding can cause allocation of large
    amounts of memory potentially consuming excessive
    resources or exhausting memory.

Additional information about these issues can be found in the OpenSSL
security advisory at https://www.openssl.org/news/secadv/20160503.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20160503.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3566"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.0.1k-3+deb8u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");
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
if (deb_check(release:"8.0", prefix:"libcrypto1.0.0-udeb", reference:"1.0.1k-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-dev", reference:"1.0.1k-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-doc", reference:"1.0.1k-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0", reference:"1.0.1k-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1k-3+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openssl", reference:"1.0.1k-3+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
