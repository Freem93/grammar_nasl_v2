#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-655-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94100);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/18 17:16:26 $");

  script_cve_id("CVE-2014-9497", "CVE-2016-1000247");
  script_bugtraq_id(65304);
  script_osvdb_id(144980);

  script_name(english:"Debian DLA-655-1 : mpg123 security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities have been discovered in mpg123, an
MPEG layer 1/2/3 audio decoder and player. An attacker could take
advantage of these flaws to cause a denial of service against mpg123
or applications using the libmpg123 library with a carefully crafted
input file.

CVE-2014-9497

Myautsai PAN discovered a flaw in the decoder initialization code of
libmpg123. A specially crafted mp3 input file can be used to cause a
buffer overflow, resulting in a denial of service.

CVE-2016-1000247

Jerold Hoong discovered a flaw in the id3 tag processing code of
libmpg123. A specially crafted mp3 input file could be used to cause a
buffer over-read, resulting in a denial of service.

For Debian 7 'Wheezy', these problems have been fixed in version
1.14.4-1+deb7u1.

We recommend that you upgrade your mpg123 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00011.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected mpg123 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mpg123");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/18");
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
if (deb_check(release:"7.0", prefix:"mpg123", reference:"1.14.4-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
