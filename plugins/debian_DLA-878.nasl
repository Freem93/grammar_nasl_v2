#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-878-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99044);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-6298", "CVE-2017-6299", "CVE-2017-6300", "CVE-2017-6301", "CVE-2017-6302", "CVE-2017-6303", "CVE-2017-6304", "CVE-2017-6305", "CVE-2017-6801", "CVE-2017-6802");
  script_osvdb_id(152488, 152489, 152490, 152491, 152492, 152493, 152494, 152495, 152496, 152497, 153357, 153358);

  script_name(english:"Debian DLA-878-1 : libytnef security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-6298 NULL pointer Deref / calloc return value not checked

CVE-2017-6299 Infinite Loop / DoS in the TNEFFillMapi function in
lib/ytnef.c

CVE-2017-6300 Buffer Overflow in version field in lib/tnef-types.h

CVE-2017-6301 Out of Bounds Reads

CVE-2017-6302 Integer Overflow

CVE-2017-6303 Invalid Write and Integer Overflow

CVE-2017-6304 Out of Bounds read

CVE-2017-6305 Out of Bounds read and write

CVE-2017-6801 Out-of-bounds access with fields of Size 0 in
TNEFParse() in libytnef

CVE-2017-6802 Heap-based buffer over-read on incoming Compressed RTF
Streams, related to DecompressRTF() in libytnef

For Debian 7 'Wheezy', these problems have been fixed in version
1.5-4+deb7u1.

We recommend that you upgrade your libytnef packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libytnef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libytnef0, and libytnef0-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libytnef0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libytnef0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
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
if (deb_check(release:"7.0", prefix:"libytnef0", reference:"1.5-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libytnef0-dev", reference:"1.5-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
