#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-563-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92570);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-6161");
  script_osvdb_id(141222);

  script_name(english:"Debian DLA-563-1 : libgd2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A global out of bounds read when encoding gif from malformed input was
found in this software.

When given invalid inputs, we might be fed the EOF marker before it is
actually the EOF. The gif logic assumes once it sees the EOF marker,
there won't be any more data, so it leaves the cur_bits index possibly
negative. So when we get more data, we underflow the masks array.

For Debian 7 'Wheezy', these problems have been fixed in version
2.0.36~rc1~dfsg-6.1+deb7u5.

We recommend that you upgrade your libgd2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/07/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgd2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2-noxpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2-noxpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2-xpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2-xpm-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
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
if (deb_check(release:"7.0", prefix:"libgd-tools", reference:"2.0.36~rc1~dfsg-6.1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-noxpm", reference:"2.0.36~rc1~dfsg-6.1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-noxpm-dev", reference:"2.0.36~rc1~dfsg-6.1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-xpm", reference:"2.0.36~rc1~dfsg-6.1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-xpm-dev", reference:"2.0.36~rc1~dfsg-6.1+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
