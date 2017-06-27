#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-99-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82244);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2014-8962", "CVE-2014-9028");
  script_bugtraq_id(71280, 71282);
  script_osvdb_id(116502);

  script_name(english:"Debian DLA-99-1 : flac security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michele Spagnuolo, of Google Security Team, and Miroslav Lichvar, of
Red Hat, discovered two issues in flac, a library handling Free
Lossless Audio Codec media: by providing a specially crafted FLAC
file, an attacker could execute arbitrary code.

CVE-2014-8962

heap-based buffer overflow in stream_decoder.c, allowing remote
attackers to execute arbitrary code via a specially crafted .flac
file.

CVE-2014-9028

stack-based buffer overflow in stream_decoder.c, allowing remote
attackers to execute arbitrary code via a specially crafted .flac
file.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/flac"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"flac", reference:"1.2.1-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libflac++-dev", reference:"1.2.1-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libflac++6", reference:"1.2.1-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libflac-dev", reference:"1.2.1-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libflac-doc", reference:"1.2.1-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libflac8", reference:"1.2.1-2+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
