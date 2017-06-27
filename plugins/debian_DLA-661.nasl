#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-661-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94102);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689");
  script_osvdb_id(144365, 144366, 144367, 144368, 144730, 147389);

  script_name(english:"Debian DLA-661-1 : libarchive security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Agostino Sarubbo of Gentoo discovered several security vulnerabilities
in libarchive, a multi-format archive and compression library. An
attacker could take advantage of these flaws to cause a buffer
overflow or an out of bounds read using a carefully crafted input
file.

CVE-2016-8687

Agostino Sarubbo of Gentoo discovered a possible stack-based buffer
overflow when printing a filename in bsdtar_expand_char() of util.c.

CVE-2016-8688

Agostino Sarubbo of Gentoo discovered a possible out of bounds read
when parsing multiple long lines in bid_entry() and detect_form() of
archive_read_support_format_mtree.c.

CVE-2016-8689

Agostino Sarubbo of Gentoo discovered a possible heap-based buffer
overflow when reading corrupted 7z files in read_Header() of
archive_read_support_format_7zip.c.

For Debian 7 'Wheezy', these problems have been fixed in version
3.0.4-3+wheezy5.

We recommend that you upgrade your libarchive packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libarchive"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdcpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"bsdcpio", reference:"3.0.4-3+wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"bsdtar", reference:"3.0.4-3+wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"libarchive-dev", reference:"3.0.4-3+wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"libarchive12", reference:"3.0.4-3+wheezy5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
