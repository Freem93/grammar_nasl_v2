#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1855. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44720);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_osvdb_id(56856);
  script_xref(name:"DSA", value:"1855");

  script_name(english:"Debian DSA-1855-1 : subversion - heap overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matt Lewis discovered that Subversion performs insufficient input
validation of svndiff streams. Malicious servers could cause heap
overflows in clients, and malicious clients with commit access could
cause heap overflows in servers, possibly leading to arbitrary code
execution in both cases."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1855"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Subversion packages.

For the old stable distribution (etch), this problem has been fixed in
version 1.4.2dfsg1-3.

For the stable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache2-svn", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-dev", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-doc", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-java", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-javahl", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-perl", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-ruby", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn-ruby1.8", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"libsvn1", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"python-subversion", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"subversion", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"4.0", prefix:"subversion-tools", reference:"1.4.2dfsg1-3")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-svn", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-dev", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-doc", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-java", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-perl", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-ruby", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-ruby1.8", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn1", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"python-subversion", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"subversion", reference:"1.5.1dfsg1-4")) flag++;
if (deb_check(release:"5.0", prefix:"subversion-tools", reference:"1.5.1dfsg1-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
