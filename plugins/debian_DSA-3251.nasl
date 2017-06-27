#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3251. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83253);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-3294");
  script_bugtraq_id(74452);
  script_osvdb_id(121174);
  script_xref(name:"DSA", value:"3251");

  script_name(english:"Debian DSA-3251-1 : dnsmasq - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nick Sampanis discovered that dnsmasq, a small caching DNS proxy and
DHCP/TFTP server, did not properly check the return value of the
setup_reply() function called during a TCP connection, which is used
then as a size argument in a function which writes data on the
client's connection. A remote attacker could exploit this issue via a
specially crafted DNS request to cause dnsmasq to crash, or
potentially to obtain sensitive information from process memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=783459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dnsmasq"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/dnsmasq"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dnsmasq packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 2.62-3+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 2.72-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"dnsmasq", reference:"2.62-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dnsmasq-base", reference:"2.62-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dnsmasq-utils", reference:"2.62-3+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"dnsmasq", reference:"2.72-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"dnsmasq-base", reference:"2.72-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"dnsmasq-utils", reference:"2.72-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
