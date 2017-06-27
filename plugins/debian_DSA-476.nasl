#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-476. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15313);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2004-0371");
  script_bugtraq_id(10035);
  script_osvdb_id(4839);
  script_xref(name:"DSA", value:"476");

  script_name(english:"Debian DSA-476-1 : heimdal - cross-realm");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to a security advisory from the heimdal project, heimdal, a
suite of software implementing the Kerberos protocol, has 'a
cross-realm vulnerability allowing someone with control over a realm
to impersonate anyone in the cross-realm trust path.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pdc.kth.se/heimdal/advisory/2004-04-01/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-476"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) this problem has been
fixed in version 0.4e-7.woody.8.1.

We recommend that you update your heimdal package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/02");
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
if (deb_check(release:"3.0", prefix:"heimdal-clients", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-clients-x", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-dev", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-docs", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-kdc", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-lib", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers-x", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libasn1-5-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libcomerr1-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libgssapi1-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libhdb7-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5clnt4-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5srv7-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libkafs0-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-17-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libotp0-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libroken9-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libsl0-heimdal", reference:"0.4e-7.woody.8.1")) flag++;
if (deb_check(release:"3.0", prefix:"libss0-heimdal", reference:"0.4e-7.woody.8.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
