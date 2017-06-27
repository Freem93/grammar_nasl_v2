#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-758. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19220);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-2040");
  script_osvdb_id(17449);
  script_xref(name:"DSA", value:"758");

  script_name(english:"Debian DSA-758-1 : heimdal - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been discovered in the telnet server from
Heimdal, a free implementation of Kerberos 5, that could lead to the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-758"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heimdal packages.

For the old stable distribution (woody) this problem has been fixed in
version 0.4e-7.woody.10.

For the stable distribution (sarge) this problem has been fixed in
version 0.6.3-10sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"heimdal-clients", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-clients-x", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-dev", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-docs", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-kdc", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-lib", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers-x", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libasn1-5-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libcomerr1-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libgssapi1-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libhdb7-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5clnt4-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5srv7-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libkafs0-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-17-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libotp0-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libroken9-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libsl0-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.0", prefix:"libss0-heimdal", reference:"0.4e-7.woody.10")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-clients", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-clients-x", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-dev", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-docs", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-kdc", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-servers", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-servers-x", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libasn1-6-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgssapi1-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libhdb7-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm5clnt4-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm5srv7-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkafs0-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-17-heimdal", reference:"0.6.3-10sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
