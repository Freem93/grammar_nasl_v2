#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3500. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89061);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-2842");
  script_xref(name:"DSA", value:"3500");

  script_name(english:"Debian DSA-3500-1 : openssl - security update");
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

  - CVE-2016-0702
    Yuval Yarom from the University of Adelaide and NICTA,
    Daniel Genkin from Technion and Tel Aviv University, and
    Nadia Heninger from the University of Pennsylvania
    discovered a side-channel attack which makes use of
    cache-bank conflicts on the Intel Sandy-Bridge
    microarchitecture. This could allow local attackers to
    recover RSA private keys.

  - CVE-2016-0705
    Adam Langley from Google discovered a double free bug
    when parsing malformed DSA private keys. This could
    allow remote attackers to cause a denial of service or
    memory corruption in applications parsing DSA private
    keys received from untrusted sources.

  - CVE-2016-0797
    Guido Vranken discovered an integer overflow in the
    BN_hex2bn and BN_dec2bn functions that can lead to a
    NULL pointer dereference and heap corruption. This could
    allow remote attackers to cause a denial of service or
    memory corruption in applications processing hex or dec
    data received from untrusted sources.

  - CVE-2016-0798
    Emilia Kasper of the OpenSSL development team
    discovered a memory leak in the SRP database lookup
    code. To mitigate the memory leak, the seed handling in
    SRP_VBASE_get_by_user is now disabled even if the user
    has configured a seed. Applications are advised to
    migrate to the SRP_VBASE_get1_by_user function.

  - CVE-2016-0799, CVE-2016-2842
    Guido Vranken discovered an integer overflow in the
    BIO_*printf functions that could lead to an OOB read
    when printing very long strings. Additionally the
    internal doapr_outch function can attempt to write to an
    arbitrary memory location in the event of a memory
    allocation failure. These issues will only occur on
    platforms where sizeof(size_t) > sizeof(int) like many
    64 bit systems. This could allow remote attackers to
    cause a denial of service or memory corruption in
    applications that pass large amounts of untrusted data
    to the BIO_*printf functions.

Additionally the EXPORT and LOW ciphers were disabled since thay could
be used as part of the DROWN (CVE-2016-0800 ) and SLOTH (CVE-2015-7575
) attacks, but note that the oldstable (wheezy) and stable (jessie)
distributions are not affected by those attacks since the SSLv2
protocol has already been dropped in the openssl package version
1.0.0c-2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7575"
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
    value:"http://www.debian.org/security/2016/dsa-3500"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.0.1e-2+deb7u20.

For the stable distribution (jessie), these problems have been fixed
in version 1.0.1k-3+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");
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
if (deb_check(release:"7.0", prefix:"libssl-dev", reference:"1.0.1e-2+deb7u20")) flag++;
if (deb_check(release:"7.0", prefix:"libssl-doc", reference:"1.0.1e-2+deb7u20")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0", reference:"1.0.1e-2+deb7u20")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1e-2+deb7u20")) flag++;
if (deb_check(release:"7.0", prefix:"openssl", reference:"1.0.1e-2+deb7u20")) flag++;
if (deb_check(release:"8.0", prefix:"libcrypto1.0.0-udeb", reference:"1.0.1k-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-dev", reference:"1.0.1k-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-doc", reference:"1.0.1k-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0", reference:"1.0.1k-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1k-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"openssl", reference:"1.0.1k-3+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
