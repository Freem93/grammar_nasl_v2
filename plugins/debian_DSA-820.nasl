#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-820. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19789);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/22 11:11:54 $");

  script_cve_id("CVE-2005-2820");
  script_osvdb_id(19262);
  script_xref(name:"DSA", value:"820");

  script_name(english:"Debian DSA-820-1 : courier - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jakob Balle discovered that with 'Conditional Comments' in Internet
Explorer it is possible to hide JavaScript code in comments that will
be executed when the browser views a malicious email via sqwebmail.
Successful exploitation requires that the user is using Internet
Explorer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=327181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-820"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sqwebmail package.

For the old stable distribution (woody) this problem has been fixed in
version 0.37.3-2.7.

For the stable distribution (sarge) this problem has been fixed in
version 0.47-4sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"courier-authdaemon", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-authmysql", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-base", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-debug", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-doc", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-imap", reference:"1.4.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-ldap", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-maildrop", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mlm", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mta", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pcp", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pop", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"courier-webadmin", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.0", prefix:"sqwebmail", reference:"0.37.3-2.7")) flag++;
if (deb_check(release:"3.1", prefix:"courier-authdaemon", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-authmysql", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-authpostgresql", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-base", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-doc", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-faxmail", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-imap", reference:"3.0.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-imap-ssl", reference:"3.0.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-ldap", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-maildrop", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-mlm", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-mta", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-mta-ssl", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-pcp", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-pop", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-pop-ssl", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-ssl", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"courier-webadmin", reference:"0.47-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sqwebmail", reference:"0.47-4sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
