#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2250. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55038);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1756");
  script_osvdb_id(73118, 73170, 73171, 73172, 73173, 73174, 73175);
  script_xref(name:"DSA", value:"2250");

  script_name(english:"Debian DSA-2250-1 : citadel - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wouter Coekaerts discovered that the Jabber server component of
Citadel, a complete and feature-rich groupware server, is vulnerable
to the so-called'billion laughs' attack because it does not prevent
entity expansion on received data. This allows an attacker to perform
denial of service attacks against the service by sending specially
crafted XML data to it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/citadel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2250"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the citadel packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 7.37-8+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 7.83-2squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:citadel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"citadel", reference:"7.37-8+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"citadel-client", reference:"7.83-2squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"citadel-dbg", reference:"7.83-2squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"citadel-doc", reference:"7.83-2squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"citadel-mta", reference:"7.83-2squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"citadel-server", reference:"7.83-2squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
