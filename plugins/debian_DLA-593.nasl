#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-593-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92874);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2016-6489");
  script_osvdb_id(142565);

  script_name(english:"Debian DLA-593-1 : nettle security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The cryptographic library nettle had a potential information leak
problem reported.

CVE-2016-6489 RSA code is vulnerable to cache sharing related attacks.

For Debian 7 'Wheezy', this problems has been fixed in version
2.4-3+deb7u1.

We recommend that you upgrade your nettle packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nettle"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhogweed2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnettle4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nettle-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nettle-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nettle-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
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
if (deb_check(release:"7.0", prefix:"libhogweed2", reference:"2.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnettle4", reference:"2.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nettle-bin", reference:"2.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nettle-dbg", reference:"2.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"nettle-dev", reference:"2.4-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
