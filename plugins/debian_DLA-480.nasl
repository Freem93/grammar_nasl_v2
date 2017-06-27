#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-480-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91242);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2016-1938", "CVE-2016-1950", "CVE-2016-1978", "CVE-2016-1979");
  script_osvdb_id(129797, 129798, 133669, 135603, 135604, 135718);

  script_name(english:"Debian DLA-480-1 : nss security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update fixes serious security issues in NSS including
arbitrary code execution and remote denial service attacks.

For Debian 7 'wheezy', these problems have been fixed in
3.14.5-1+deb7u6. We recommend you upgrade your nss packages as soon as
possible.

CVE-2015-7181

The sec_asn1d_parse_leaf function improperly restricts access to an
unspecified data structure.

CVE-2015-7182

Heap-based buffer overflow in the ASN.1 decoder.

CVE-2016-1938

The s_mp_div function in lib/freebl/mpi/mpi.c in improperly divides
numbers, which might make it easier for remote attackers to defeat
cryptographic protection mechanisms.

CVE-2016-1950

Heap-based buffer overflow allows remote attackers to execute
arbitrary code via crafted ASN.1 data in an X.509 certificate.

CVE-2016-1978

Use-after-free vulnerability in the ssl3_HandleECDHServerKeyExchange
function allows remote attackers to cause a denial of service or
possibly have unspecified other impact by making an SSL (1) DHE or (2)
ECDHE handshake at a time of high memory consumption.

CVE-2016-1979

Use-after-free vulnerability in the
PK11_ImportDERPrivateKeyInfoAndReturnKey function allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via crafted key data with DER encoding.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nss"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
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
if (deb_check(release:"7.0", prefix:"libnss3", reference:"3.14.5-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-1d", reference:"3.14.5-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dbg", reference:"3.14.5-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dev", reference:"3.14.5-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-tools", reference:"3.14.5-1+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
