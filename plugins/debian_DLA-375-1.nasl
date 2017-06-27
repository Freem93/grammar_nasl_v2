#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were
# extracted from Debian Security Advisory DLA-375-1.
#

include("compat.inc");

if (description)
{
  script_id(92678);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id(
    "CVE-2012-3425",
    "CVE-2015-8472",
    "CVE-2015-8540"
  );
  script_bugtraq_id(
    54652,
    78624,
    80592
  );
  script_osvdb_id(
    84389,
    130175,
    131598
  );

  script_name(english:"Debian DLA-375-1 : libpng Security Update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian host is running a version of libpng prior to
1.2.44-1+squeeze6. It is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read error exists in the
    png_push_read_zTXt() function within file pngpread.c
    when decompressing PNG images. An unauthenticated,
    remote attacker can exploit this, via a large 'avail_in'
    field to cause a denial of service condition.
    (CVE-2012-3425)

  - A buffer overflow condition exists in the png_set_PLTE()
    function within file pngset.c and the png_get_PLTE()
    function within file pngget.c when handling bit-depth
    values less than 8. An unauthenticated, remote attacker
    can exploit this, via a specially crafted IHDR chunk
    in a PNG image, to cause a denial of service or have
    other unspecified impact. (CVE-2015-8472)

  - An integer underflow condition exists in the
    png_check_keyword() function within file pngwutil.c. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted PNG image using a space character as
    a keyword, to cause a denial of service condition or
    other unspecified impact. (CVE-2015-8540)");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00017.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng12-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng12-0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
if (deb_check(release:"6.0", prefix:"libpng12-0", reference:"1.2.44-1+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-0-udeb", reference:"1.2.44-1+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-dev", reference:"1.2.44-1+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libpng3", reference:"1.2.44-1+squeeze6")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
