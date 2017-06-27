#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-893-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99271);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/11 16:24:59 $");

  script_cve_id("CVE-2015-6644");
  script_osvdb_id(132512);

  script_name(english:"Debian DLA-893-1 : bouncycastle security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information disclosure vulnerability was discovered in Bouncy
Castle, a Java library which consists of various cryptographic
algorithms. The Galois/Counter mode (GCM) implementation was missing a
boundary check that could enable a local application to gain access to
user's private information.

For Debian 7 'Wheezy', these problems have been fixed in version
1.44+dfsg-3.1+deb7u2.

We recommend that you upgrade your bouncycastle packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bouncycastle"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libbcmail-java", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcmail-java-doc", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcmail-java-gcj", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcpg-java", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcpg-java-doc", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcpg-java-gcj", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcprov-java", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcprov-java-doc", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbcprov-java-gcj", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbctsp-java", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbctsp-java-doc", reference:"1.44+dfsg-3.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libbctsp-java-gcj", reference:"1.44+dfsg-3.1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
