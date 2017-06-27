#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3473. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88702);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747");
  script_xref(name:"DSA", value:"3473");

  script_name(english:"Debian DSA-3473-1 : nginx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the resolver in nginx, a
small, powerful, scalable web/proxy server, leading to denial of
service or, potentially, to arbitrary code execution. These only
affect nginx if the 'resolver' directive is used in a configuration
file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3473"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nginx packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.2.1-2.2+wheezy4.

For the stable distribution (jessie), these problems have been fixed
in version 1.6.2-5+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");
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
if (deb_check(release:"7.0", prefix:"nginx", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-common", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-doc", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-extras", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-extras-dbg", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-full", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-full-dbg", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-light", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-light-dbg", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi-dbg", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi-ui", reference:"1.2.1-2.2+wheezy4")) flag++;
if (deb_check(release:"8.0", prefix:"nginx", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-common", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-doc", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras-dbg", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full-dbg", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light", reference:"1.6.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light-dbg", reference:"1.6.2-5+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
