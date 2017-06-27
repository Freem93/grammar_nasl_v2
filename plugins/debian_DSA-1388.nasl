#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1388. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27515);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-5365", "CVE-2008-5010");
  script_osvdb_id(41687);
  script_xref(name:"DSA", value:"1388");

  script_name(english:"Debian DSA-1388-3 : dhcp - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The patch used to correct the DHCP server buffer overflow in
DSA-1388-1 was incomplete and did not adequately resolve the problem.
This update to the previous advisory makes updated packages based on a
newer version of the patch available.

For completeness, please find below the original advisory :

It was discovered that dhcp, a DHCP server for automatic IP address
assignment, didn't correctly allocate space for network replies. This
could potentially allow a malicious DHCP client to execute arbitrary
code upon the DHCP server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=446354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1388"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dhcp packages.

For the stable distribution (etch), this problem has been fixed in
version 2.0pl5-19.5etch2.

Updates to the old stable version (sarge) are pending."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"dhcp", reference:"2.0pl5-19.5etch2")) flag++;
if (deb_check(release:"3.1", prefix:"dhcp-client", reference:"2.0pl5-19.5etch2")) flag++;
if (deb_check(release:"3.1", prefix:"dhcp-relay", reference:"2.0pl5-19.5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp", reference:"2.0pl5-19.5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp-client", reference:"2.0pl5-19.5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp-relay", reference:"2.0pl5-19.5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
