#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-120. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14957);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2002-0082");
  script_osvdb_id(756);
  script_xref(name:"DSA", value:"120");

  script_name(english:"Debian DSA-120-1 : mod_ssl - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ed Moyle recently found a buffer overflow in Apache-SSL and mod_ssl.
With session caching enabled, mod_ssl will serialize SSL session
variables to store them for later use. These variables were stored in
a buffer of a fixed size without proper boundary checks.

To exploit the overflow, the server must be configured to require
client certificates, and an attacker must obtain a carefully crafted
client certificate that has been signed by a Certificate Authority
which is trusted by the server. If these conditions are met, it would
be possible for an attacker to execute arbitrary code on the server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2002-02/0313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-120"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Apache-SSL and mod_ssl packages.

This problem has been fixed in version 1.3.9.13-4 of Apache-SSL and
version 2.4.10-1.3.9-1potato1 of libapache-mod-ssl for the stable
Debian distribution as well as in version 1.3.23.1+1.47-1 of
Apache-SSL and version 2.8.7-1 of libapache-mod-ssl for the testing
and unstable distribution of Debian."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/27");
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
if (deb_check(release:"2.2", prefix:"apache-ssl", reference:"1.3.9.13-4")) flag++;
if (deb_check(release:"2.2", prefix:"libapache-mod-ssl", reference:"2.4.10-1.3.9-1potato1")) flag++;
if (deb_check(release:"2.2", prefix:"libapache-mod-ssl-doc", reference:"2.4.10-1.3.9-1potato1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
