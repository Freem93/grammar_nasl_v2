#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-691-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94448);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-4658", "CVE-2016-5131");
  script_osvdb_id(141934, 144561);

  script_name(english:"Debian DLA-691-1 : libxml2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-4658 Namespace nodes must be copied to avoid use-after-free
errors. But they don't necessarily have a physical representation in a
document, so simply disallow them in XPointer ranges.

CVE-2016-5131 The old code would invoke the broken
xmlXPtrRangeToFunction. range-to isn't really a function but a special
kind of location step. Remove this function and always handle range-to
in the XPath code. The old xmlXPtrRangeToFunction could also be abused
to trigger a use-after-free error with the potential for remote code
execution.

For Debian 7 'Wheezy', these problems have been fixed in version
2.8.0+dfsg1-7+wheezy7.

We recommend that you upgrade your libxml2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libxml2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/01");
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
if (deb_check(release:"7.0", prefix:"libxml2", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-dbg", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-dev", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-doc", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-utils", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libxml2-utils-dbg", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"python-libxml2", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"python-libxml2-dbg", reference:"2.8.0+dfsg1-7+wheezy7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
