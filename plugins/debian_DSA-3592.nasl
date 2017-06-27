#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3592. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91431);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-4450");
  script_osvdb_id(139239);
  script_xref(name:"DSA", value:"3592");

  script_name(english:"Debian DSA-3592-1 : nginx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a NULL pointer dereference in the Nginx code
responsible for saving client request bodies to a temporary file might
result in denial of service: Malformed requests could crash worker
processes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3592"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nginx packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.6.2-5+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/02");
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
if (deb_check(release:"8.0", prefix:"nginx", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-common", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-doc", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras-dbg", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full-dbg", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light", reference:"1.6.2-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light-dbg", reference:"1.6.2-5+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
