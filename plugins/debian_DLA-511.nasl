#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-511-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91575);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-5301");
  script_osvdb_id(139318);

  script_name(english:"Debian DLA-511-1 : libtorrent-rasterbar security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A specially crafted HTTP response from a tracker (or potentially a
UPnP broadcast) can crash libtorrent in the parse_chunk_header()
function. Although this function is not present in this version,
upstream's additional sanity checks were added to abort the program if
necessary instead of crashing it.

For Debian 7 'Wheezy', these problems have been fixed in version
0.15.10-1+deb7u1.

We recommend that you upgrade your libtorrent-rasterbar packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/06/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libtorrent-rasterbar"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libtorrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libtorrent-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");
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
if (deb_check(release:"7.0", prefix:"libtorrent-rasterbar-dbg", reference:"0.15.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtorrent-rasterbar-dev", reference:"0.15.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtorrent-rasterbar-doc", reference:"0.15.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtorrent-rasterbar6", reference:"0.15.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-libtorrent", reference:"0.15.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-libtorrent-dbg", reference:"0.15.10-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
