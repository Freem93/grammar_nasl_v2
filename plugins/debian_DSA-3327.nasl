#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3327. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85184);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/30 13:50:19 $");

  script_cve_id("CVE-2015-5400");
  script_xref(name:"DSA", value:"3327");

  script_name(english:"Debian DSA-3327-1 : squid3 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alex Rousskov of The Measurement Factory discovered that Squid3, a
fully featured web proxy cache, does not correctly handle CONNECT
method peer responses when configured with cache_peer and operating on
explicit proxy traffic. This could allow remote clients to gain
unrestricted access through a gateway proxy to its backend proxy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=793128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3327"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid3 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 3.1.20-2.2+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 3.4.8-6+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
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
if (deb_check(release:"7.0", prefix:"squid-cgi", reference:"3.1.20-2.2+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"squid3", reference:"3.1.20-2.2+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"squid3-common", reference:"3.1.20-2.2+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"squid3-dbg", reference:"3.1.20-2.2+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"squidclient", reference:"3.1.20-2.2+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"squid-cgi", reference:"3.4.8-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squid-purge", reference:"3.4.8-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squid3", reference:"3.4.8-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squid3-common", reference:"3.4.8-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squid3-dbg", reference:"3.4.8-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squidclient", reference:"3.4.8-6+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
