#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3371. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86329);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/10 14:05:03 $");

  script_cve_id("CVE-2015-5260", "CVE-2015-5261");
  script_xref(name:"DSA", value:"3371");

  script_name(english:"Debian DSA-3371-1 : spice - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Frediano Ziglio of Red Hat discovered several vulnerabilities in
spice, a SPICE protocol client and server library. A malicious guest
can exploit these flaws to cause a denial of service (QEMU process
crash), execute arbitrary code on the host with the privileges of the
hosting QEMU process or read and write arbitrary memory locations on
the host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=801089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=801091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/spice"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/spice"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3371"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the spice packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 0.11.0-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed
in version 0.12.5-1+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libspice-server-dev", reference:"0.11.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libspice-server1", reference:"0.11.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"spice-client", reference:"0.11.0-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server-dev", reference:"0.12.5-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server1", reference:"0.12.5-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server1-dbg", reference:"0.12.5-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"spice-client", reference:"0.12.5-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
