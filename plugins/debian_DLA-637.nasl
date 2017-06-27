#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-637-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93690);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_osvdb_id(139313, 139471, 142095, 143021, 143259, 143309, 143389, 143392, 144687, 144688);

  script_name(english:"Debian DLA-637-1 : openssl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in OpenSSL :

CVE-2016-2177

Guido Vranken discovered that OpenSSL uses undefined pointer
arithmetic. Additional information can be found at
https://www.openssl.org/blog/blog/2016/06/27/undefined-pointer-arithme
tic/

CVE-2016-2178

Cesar Pereida, Billy Brumley and Yuval Yarom discovered a timing leak
in the DSA code.

CVE-2016-2179 / CVE-2016-2181

Quan Luo and the OCAP audit team discovered denial of service
vulnerabilities in DTLS.

CVE-2016-2180 / CVE-2016-2182 / CVE-2016-6303

Shi Lei discovered an out-of-bounds memory read in TS_OBJ_print_bio()
and an out-of-bounds write in BN_bn2dec() and MDC2_Update().

CVE-2016-2183

DES-based cipher suites are demoted from the HIGH group to MEDIUM as a
mitigation for the SWEET32 attack.

CVE-2016-6302

Shi Lei discovered that the use of SHA512 in TLS session tickets is
susceptible to denial of service.

CVE-2016-6304

Shi Lei discovered that excessively large OCSP status request may
result in denial of service via memory exhaustion.

CVE-2016-6306

Shi Lei discovered that missing message length validation when parsing
certificates may potentially result in denial of service.

For Debian 7 'Wheezy', these problems have been fixed in version
1.0.1t-1+deb7u1.

We recommend that you upgrade your openssl and libssl1.0.0 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssl"
  );
  # https://www.openssl.org/blog/blog/2016/06/27/undefined-pointer-arithmetic/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6824788b"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.0.0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");
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
if (deb_check(release:"7.0", prefix:"libssl-dev", reference:"1.0.1t-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libssl-doc", reference:"1.0.1t-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0", reference:"1.0.1t-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1t-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openssl", reference:"1.0.1t-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
