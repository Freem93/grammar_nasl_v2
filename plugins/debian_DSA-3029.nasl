#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3029. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77762);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-3616");
  script_xref(name:"DSA", value:"3029");

  script_name(english:"Debian DSA-3029-1 : nginx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Antoine Delignat-Lavaud and Karthikeyan Bhargavan discovered that it
was possible to reuse cached SSL sessions in unrelated contexts,
allowing virtual host confusion attacks in some configurations by an
attacker in a privileged network position."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=761940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3029"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nginx packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.2.1-2.2+wheezy3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"nginx", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-common", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-doc", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-extras", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-extras-dbg", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-full", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-full-dbg", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-light", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-light-dbg", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi-dbg", reference:"1.2.1-2.2+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"nginx-naxsi-ui", reference:"1.2.1-2.2+wheezy3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
