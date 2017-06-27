#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-361-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87266);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:23:47 $");

  script_cve_id("CVE-2015-7940");
  script_osvdb_id(129389);

  script_name(english:"Debian DLA-361-1 : bouncycastle security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Bouncy Castle Java library before 1.51 does not validate that a
point is within the elliptic curve, which makes it easier for remote
attackers to obtain private keys via a series of crafted elliptic
curve Diffie Hellman (ECDH) key exchanges, aka an 'invalid curve
attack.'

For Debian 6 'Squeeze', this issue has been fixed in
version 1.44+dfsg-2+deb6u1 of bouncycastle.

Many thanks to upstream author Peter Dettmann who reviewed the
backport that we prepared.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/bouncycastle"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbctsp-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbctsp-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbctsp-java-gcj");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/09");
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
if (deb_check(release:"6.0", prefix:"libbcmail-java", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcmail-java-doc", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcmail-java-gcj", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcpg-java", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcpg-java-doc", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcpg-java-gcj", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcprov-java", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcprov-java-doc", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbcprov-java-gcj", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbctsp-java", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbctsp-java-doc", reference:"1.44+dfsg-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libbctsp-java-gcj", reference:"1.44+dfsg-2+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
