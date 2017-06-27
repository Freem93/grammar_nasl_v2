#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-312-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86022);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_cve_id("CVE-2015-5685");
  script_osvdb_id(125524, 125525);

  script_name(english:"Debian DLA-312-1 : libtorrent-rasterbar security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The lazy_bdecode function in BitTorrent DHT bootstrap server
(bootstrap-dht ) allows remote attackers to execute arbitrary code via
a crafted packet, related to 'improper indexing.'

Note while this CVE was reported against BitTorrent DHT Bootstrapt
server, the same vulnerable code is available in libtorrent-rasterbar.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libtorrent-rasterbar"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorrent-rasterbar5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libtorrent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libtorrent-rasterbar-dbg", reference:"0.14.10-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libtorrent-rasterbar-dev", reference:"0.14.10-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libtorrent-rasterbar-doc", reference:"0.14.10-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libtorrent-rasterbar5", reference:"0.14.10-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"python-libtorrent", reference:"0.14.10-2+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
