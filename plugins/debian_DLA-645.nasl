#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-645-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93868);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-2775", "CVE-2016-2776");
  script_osvdb_id(141681, 144854);
  script_xref(name:"IAVA", value:"2017-A-0004");

  script_name(english:"Debian DLA-645-1 : bind9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-2775

lwresd crash with long query name Backport of upstream commit
38cc2d14e218e536e0102fa70deef99461354232.

CVE-2016-2776

assertion failure due to unspecified crafted query Fix based on
43139-9-9.patch from ISC.

For Debian 7 'Wheezy', these problems have been fixed in version
1:9.8.4.dfsg.P1-6+nmu2+deb7u11.

We recommend that you upgrade your bind9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bind9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns88");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg82");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"7.0", prefix:"bind9", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-doc", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"bind9utils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"dnsutils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libbind-dev", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libbind9-80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libdns88", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libisc84", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libisccc80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libisccfg82", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"liblwres80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"lwresd", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
