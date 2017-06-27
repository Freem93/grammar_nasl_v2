#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-178. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15015);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:49:56 $");

  script_cve_id("CVE-2002-1225", "CVE-2002-1226", "CVE-2002-1235");
  script_osvdb_id(4900, 5616, 5617, 5618);
  script_xref(name:"CERT", value:"875073");
  script_xref(name:"DSA", value:"178");

  script_name(english:"Debian DSA-178-1 : heimdal - remote command execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SuSE Security Team has reviewed critical parts of the Heimdal
package such as the kadmind and kdc server. While doing so several
potential buffer overflows and other bugs have been uncovered and
fixed. Remote attackers can probably gain remote root access on
systems without fixes. Since these services usually run on
authentication servers these bugs are considered very serious.

These problems have been fixed in version 0.4e-7.woody.4 for the
current stable distribution (woody), in version 0.2l-7.4 for the old
stable distribution (potato) and version 0.4e-21 for the unstable
distribution (sid)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-178"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the Heimdal packages immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"heimdal-clients", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-clients-x", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-dev", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-docs", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-kdc", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-lib", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-servers", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"2.2", prefix:"heimdal-servers-x", reference:"0.2l-7.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-clients", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-clients-x", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-dev", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-docs", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-kdc", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-lib", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers-x", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libasn1-5-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libcomerr1-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libgssapi1-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libhdb7-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5clnt4-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5srv7-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libkafs0-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-17-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libotp0-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libroken9-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libsl0-heimdal", reference:"0.4e-7.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libss0-heimdal", reference:"0.4e-7.woody.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
