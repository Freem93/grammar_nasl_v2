#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1970. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44835);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:40 $");

  script_cve_id("CVE-2009-4355");
  script_bugtraq_id(31692);
  script_osvdb_id(61684);
  script_xref(name:"DSA", value:"1970");

  script_name(english:"Debian DSA-1970-1 : openssl - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a significant memory leak could occur in
OpenSSL, related to the reinitialization of zlib. This could result in
a remotely exploitable denial of service vulnerability when using the
Apache httpd server in a configuration where mod_ssl, mod_php5, and
the php5-curl extension are loaded."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1970"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages. You also need to restart the Apache
httpd server to make sure it uses the updated libraries.

The old stable distribution (etch) is not affected by this issue.

For the stable distribution (lenny), this problem has been fixed in
version 0.9.8g-15+lenny6.

The packages for the arm architecture are not included in this
advisory. They will be released as soon as they become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libssl-dev", reference:"0.9.8g-15+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8", reference:"0.9.8g-15+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8g-15+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
