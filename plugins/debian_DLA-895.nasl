#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-895-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99401);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_name(english:"Debian DLA-895-1 : openoffice.org-dictionaries update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The dictionaries provided by this package had an unversioned conflict
against the thunderbird package (which so far was not part of wheezy).

Since the next update of Icedove introduces a thunderbird package the
dictionaries would become unusable in Icedove so the (unneeded)
conflict was dropped.

For Debian 7 'Wheezy', this problem has been fixed in version
3.3.0~rc10-4+deb7u1.

We recommend that you upgrade your openoffice.org-dictionaries
packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openoffice.org-dictionaries"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-de-at-frami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-de-ch-frami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-de-de-frami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-sh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hunspell-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-sh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyphen-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:myspell-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mythes-sk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");
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
if (deb_check(release:"7.0", prefix:"hunspell-da", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-de-at-frami", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-de-ch-frami", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-de-de-frami", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-en-ca", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-fr", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-hu", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-ne", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-ro", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-sh", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-sr", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hunspell-vi", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-af", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-ca", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-de", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-fr", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-hu", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-it", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-ro", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-sh", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-sl", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-sr", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hyphen-zu", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-af", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-en-gb", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-en-us", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-en-za", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-it", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-sw", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"myspell-th", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-ca", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-cs", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-en-us", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-fr", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-hu", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-ne", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-ro", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-ru", reference:"3.3.0~rc10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mythes-sk", reference:"3.3.0~rc10-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
