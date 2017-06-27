#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1379. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26209);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343", "CVE-2007-5135");
  script_osvdb_id(29260, 29261, 29262, 29263);
  script_xref(name:"DSA", value:"1379");

  script_name(english:"Debian DSA-1379-1 : openssl - off-by-one error/buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An off-by-one error has been identified in the
SSL_get_shared_ciphers() routine in the libssl library from OpenSSL,
an implementation of Secure Socket Layer cryptographic libraries and
utilities. This error could allow an attacker to crash an application
making use of OpenSSL's libssl library, or potentially execute
arbitrary code in the security context of the user running such an
application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=444435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1379"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the old stable distribution (sarge), this problem has been fixed
in version 0.9.7e-3sarge5.

For the stable distribution (etch), this problem has been fixed in
version 0.9.8c-4etch1.

For the unstable and testing distributions (sid and lenny,
respectively), this problem has been fixed in version 0.9.8e-9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libssl-dev", reference:"0.9.7e-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libssl0.9.7", reference:"0.9.7e-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"openssl", reference:"0.9.7e-3sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"libssl-dev", reference:"0.9.8c-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8", reference:"0.9.8c-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8c-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openssl", reference:"0.9.8c-4etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
