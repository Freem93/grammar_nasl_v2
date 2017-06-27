#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-890-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99268);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/13 13:33:09 $");

  script_cve_id("CVE-2017-7578");
  script_osvdb_id(148230);

  script_name(english:"Debian DLA-890-1 : ming security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there were multiple heap-based buffer overflows
in ming, a library to generate SWF (Flash) files.

The updated packages prevent a crash in the 'listswf' utility due to a
heap-based buffer overflow in the parseSWF_RGBA function and several
other functions in parser.c.

AddressSanitizer flagged them as invalid writes 'of size 1' but the
heap could be written to multiple times. The overflows are caused by a
pointer behind the bounds of a statically allocated array of structs
of type SWF_GRADIENTRECORD.

For Debian 7 'Wheezy', this issue has been fixed in ming version
1:0.4.4-1.1+deb7u2.

We recommend that you upgrade your ming packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ming"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
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
if (deb_check(release:"7.0", prefix:"libming-dev", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libming-util", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libming1", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libswf-perl", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ming-fonts-dejavu", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ming-fonts-opensymbol", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ming", reference:"1:0.4.4-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-ming", reference:"1:0.4.4-1.1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
