#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3519. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90030);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8550", "CVE-2015-8555", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-2270", "CVE-2016-2271");
  script_osvdb_id(131284, 131285, 131453, 132029, 132050, 133503, 133504, 134693, 134694);
  script_xref(name:"DSA", value:"3519");

  script_name(english:"Debian DSA-3519-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in the Xen virtualisation
solution, which may result in denial of service or information
disclosure.

The oldstable distribution (wheezy) will be updated in a separate DSA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3519"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (jessie), these problems have been fixed
in version 4.4.1-9+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
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
if (deb_check(release:"8.0", prefix:"libxen-4.4", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libxen-dev", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libxenstore3.0", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-amd64", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-arm64", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-armhf", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-amd64", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-arm64", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-armhf", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-4.4", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-common", reference:"4.4.1-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xenstore-utils", reference:"4.4.1-9+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
