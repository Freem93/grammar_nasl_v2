#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3565. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90841);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-5726", "CVE-2015-5727", "CVE-2015-7827", "CVE-2016-2194", "CVE-2016-2195", "CVE-2016-2849");
  script_osvdb_id(128329, 128330, 130452, 134082, 134083, 136203);
  script_xref(name:"DSA", value:"3565");

  script_name(english:"Debian DSA-3565-1 : botan1.10 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were found in botan1.10, a C++
library which provides support for many common cryptographic
operations, including encryption, authentication, X.509v3 certificates
and CRLs.

  - CVE-2015-5726
    The BER decoder would crash due to reading from offset 0
    of an empty vector if it encountered a BIT STRING which
    did not contain any data at all. This can be used to
    easily crash applications reading untrusted ASN.1 data,
    but does not seem exploitable for code execution.

  - CVE-2015-5727
    The BER decoder would allocate a fairly arbitrary amount
    of memory in a length field, even if there was no chance
    the read request would succeed. This might cause the
    process to run out of memory or invoke the OOM killer.

  - CVE-2015-7827
    Use constant time PKCS #1 unpadding to avoid possible
    side channel attack against RSA decryption

  - CVE-2016-2194
    Infinite loop in modular square root algorithm. The
    ressol function implementing the Tonelli-Shanks
    algorithm for finding square roots could be sent into a
    nearly infinite loop due to a misplaced conditional
    check. This could occur if a composite modulus is
    provided, as this algorithm is only defined for primes.
    This function is exposed to attacker controlled input
    via the OS2ECP function during ECC point decompression.

  - CVE-2016-2195
    Fix Heap overflow on invalid ECC point.

  - CVE-2016-2849
    Use constant time modular inverse algorithm to avoid
    possible side channel attack against ECDSA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=817932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=822698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/botan1.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3565"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the botan1.10 packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.10.8-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:botan1.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
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
if (deb_check(release:"8.0", prefix:"botan1.10-dbg", reference:"1.10.8-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbotan-1.10-0", reference:"1.10.8-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbotan1.10-dev", reference:"1.10.8-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
