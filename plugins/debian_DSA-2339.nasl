#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2339. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56729);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-3640");
  script_osvdb_id(76858);
  script_xref(name:"DSA", value:"2339");

  script_name(english:"Debian DSA-2339-1 : nss - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to the NSS cryptographic libraries revokes the trust in
the'DigiCert Sdn. Bhd' certificate authority. More information can be
found in the Mozilla Security Blog.

This update also fixes an insecure load path for pkcs11.txt
configuration file (CVE-2011-3640 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=647614"
  );
  # http://blog.mozilla.com/security/2011/11/03/revoking-trust-in-digicert-sdn-bhd-intermediate-certificate-authority/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71e2509a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2339"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.12.3.1-0lenny7.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/08");
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
if (deb_check(release:"5.0", prefix:"nss", reference:"3.12.3.1-0lenny7")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-1d", reference:"3.12.8-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-1d-dbg", reference:"3.12.8-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-dev", reference:"3.12.8-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-tools", reference:"3.12.8-1+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
