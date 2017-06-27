#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-850. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19958);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-1279");
  script_osvdb_id(15863, 15864);
  script_xref(name:"DSA", value:"850");

  script_name(english:"Debian DSA-850-1 : tcpdump - infinite loop");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'Vade 79' discovered that the BGP dissector in tcpdump, a powerful
tool for network monitoring and data acquisition, does not properly
handle RT_ROUTING_INFO. A specially crafted BGP packet can cause a
denial of service via an infinite loop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-850"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tcpdump package.

For the old stable distribution (woody) this problem has been fixed in
version 3.6.2-2.9.

For the stable distribution (sarge) this problem has been fixed in
version 3.8.3-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/26");
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
if (deb_check(release:"3.0", prefix:"tcpdump", reference:"3.6.2-2.9")) flag++;
if (deb_check(release:"3.1", prefix:"tcpdump", reference:"3.8.3-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
