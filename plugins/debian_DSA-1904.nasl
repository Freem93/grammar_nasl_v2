#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1904. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44769);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-3490");
  script_bugtraq_id(36205);
  script_xref(name:"DSA", value:"1904");

  script_name(english:"Debian DSA-1904-1 : wget - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Stenberg discovered that wget, a network utility to retrieve
files from the Web using HTTP(S) and FTP, is vulnerable to the 'Null
Prefix Attacks Against SSL/TLS Certificates' published at the Blackhat
conference some time ago. This allows an attacker to perform
undetected man-in-the-middle attacks via a crafted ITU-T X.509
certificate with an injected null byte in the Common Name field."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=549293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1904"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wget packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.10.2-2+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 1.11.4-2+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/09");
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
if (deb_check(release:"4.0", prefix:"wget", reference:"1.10.2-2+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"wget", reference:"1.11.4-2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
