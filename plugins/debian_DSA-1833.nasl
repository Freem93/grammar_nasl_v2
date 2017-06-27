#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1833. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44698);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0692", "CVE-2009-1892");
  script_bugtraq_id(35668, 35669);
  script_osvdb_id(56422);
  script_xref(name:"CERT", value:"410676");
  script_xref(name:"DSA", value:"1833");

  script_name(english:"Debian DSA-1833-1 : dhcp3 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in ISC's DHCP
implementation :

  - CVE-2009-0692
    It was discovered that dhclient does not properly handle
    overlong subnet mask options, leading to a stack-based
    buffer overflow and possible arbitrary code execution.

  - CVE-2009-1892
    Christoph Biedl discovered that the DHCP server may
    terminate when receiving certain well-formed DHCP
    requests, provided that the server configuration mixes
    host definitions using 'dhcp-client-identifier' and
    'hardware ethernet'. This vulnerability only affects the
    lenny versions of dhcp3-server and dhcp3-server-ldap."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1833"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dhcp3 packages.

For the old stable distribution (etch), these problems have been fixed
in version 3.0.4-13+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 3.1.1-6+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
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
if (deb_check(release:"4.0", prefix:"dhcp3-client", reference:"3.0.4-13+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp3-common", reference:"3.0.4-13+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp3-dev", reference:"3.0.4-13+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp3-relay", reference:"3.0.4-13+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dhcp3-server", reference:"3.0.4-13+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp-client", reference:"3.1.1-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp3-client", reference:"3.1.1-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp3-common", reference:"3.1.1-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp3-dev", reference:"3.1.1-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp3-relay", reference:"3.1.1-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp3-server", reference:"3.1.1-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"dhcp3-server-ldap", reference:"3.1.1-6+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
