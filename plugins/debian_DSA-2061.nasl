#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2061. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47103);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2010-2063");
  script_bugtraq_id(40884);
  script_osvdb_id(65518);
  script_xref(name:"DSA", value:"2061");

  script_name(english:"Debian DSA-2061-1 : samba - memory corruption");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jun Mao discovered that Samba, an implementation of the SMB/CIFS
protocol for Unix systems, is not properly handling certain offset
values when processing chained SMB1 packets. This enables an
unauthenticated attacker to write to an arbitrary memory location
resulting in the possibility to execute arbitrary code with root
privileges or to perform denial of service attacks by crashing the
samba daemon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2061"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (lenny), this problem has been fixed in
version 3.2.5-4lenny12.

This problem does not affect the versions in the testing (squeeze) and
unstable (sid) distribution."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba chain_reply Memory Corruption (Linux x86)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/21");
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
if (deb_check(release:"5.0", prefix:"libpam-smbpass", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient-dev", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"libwbclient0", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"samba", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"samba-common", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"samba-dbg", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc-pdf", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"samba-tools", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"smbclient", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"smbfs", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"swat", reference:"3.2.5-4lenny12")) flag++;
if (deb_check(release:"5.0", prefix:"winbind", reference:"3.2.5-4lenny12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
