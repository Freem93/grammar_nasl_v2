#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-867-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97921);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id("CVE-2017-6829", "CVE-2017-6830", "CVE-2017-6831", "CVE-2017-6832", "CVE-2017-6833", "CVE-2017-6834", "CVE-2017-6835", "CVE-2017-6836", "CVE-2017-6837", "CVE-2017-6838", "CVE-2017-6839");
  script_osvdb_id(152670, 152671, 152672, 152673, 152674, 152675, 152676, 152677, 153513);

  script_name(english:"Debian DLA-867-1 : audiofile security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found in audiofile.

CVE-2017-6829

Allows remote attackers to cause a denial of service (crash) via a
crafted file.

CVE-2017-6830, CVE-2017-6834, CVE-2017-6831, CVE-2017-6832,
CVE-2017-6838, CVE-2017-6839, CVE-2017-6836

Heap-based buffer overflow in that allows remote attackers to cause a
denial of service (crash) via a crafted file.

CVE-2017-6833, CVE-2017-6835

The runPull function allows remote attackers to cause a denial of
service (divide-by-zero error and crash) via a crafted file.

CVE-2017-6837

Allows remote attackers to cause a denial of service (crash) via
vectors related to a large number of coefficients.

For Debian 7 'Wheezy', these problems have been fixed in version
0.3.4-2+deb7u1.

We recommend that you upgrade your audiofile packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/audiofile"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:audiofile-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libaudiofile-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libaudiofile-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libaudiofile1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");
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
if (deb_check(release:"7.0", prefix:"audiofile-tools", reference:"0.3.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libaudiofile-dbg", reference:"0.3.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libaudiofile-dev", reference:"0.3.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libaudiofile1", reference:"0.3.4-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
