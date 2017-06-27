#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3355. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85898);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/11 13:39:47 $");

  script_cve_id("CVE-2015-5198", "CVE-2015-5199", "CVE-2015-5200");
  script_xref(name:"DSA", value:"3355");

  script_name(english:"Debian DSA-3355-1 : libvdpau - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Weimer of Red Hat Product Security discovered that libvdpau,
the VDPAU wrapper library, did not properly validate environment
variables, allowing local attackers to gain additional privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=797895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libvdpau"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvdpau"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3355"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvdpau packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 0.4.1-7+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 0.8-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvdpau");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libvdpau-dev", reference:"0.4.1-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libvdpau-doc", reference:"0.4.1-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libvdpau1", reference:"0.4.1-7+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvdpau-dev", reference:"0.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvdpau-doc", reference:"0.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvdpau1", reference:"0.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvdpau1-dbg", reference:"0.8-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
