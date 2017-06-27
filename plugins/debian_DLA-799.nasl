#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-799-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96814);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2016-9264", "CVE-2016-9265", "CVE-2016-9266", "CVE-2016-9827", "CVE-2016-9828", "CVE-2016-9829", "CVE-2016-9831");
  script_osvdb_id(147089, 147094, 147112, 148230, 148231, 148232, 148233);

  script_name(english:"Debian DLA-799-1 : ming security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Ming. They may lead to the
execution of arbitrary code or causing application crash.

CVE-2016-9264

global-buffer-overflow in printMP3Headers

CVE-2016-9265

divide-by-zero in printMP3Headers

CVE-2016-9266

left shift in listmp3.c

CVE-2016-9827

listswf: heap-based buffer overflow in _iprintf

CVE-2016-9828

listswf: heap-based buffer overflow in _iprintf

CVE-2016-9829

listswf: NULL pointer dereference in dumpBuffer

CVE-2016-9831

listswf: heap-based buffer overflow in parseSWF_RGBA

For Debian 7 'Wheezy', these problems have been fixed in version
0.4.4-1.1+deb7u1.

We recommend that you upgrade your ming packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ming"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libming-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libming-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libming1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswf-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ming-fonts-dejavu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ming-fonts-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-ming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ming");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");
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
if (deb_check(release:"7.0", prefix:"libming-dev", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libming-util", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libming1", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswf-perl", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ming-fonts-dejavu", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ming-fonts-opensymbol", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ming", reference:"1:0.4.4-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-ming", reference:"1:0.4.4-1.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
