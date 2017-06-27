#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-557. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15655);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0564");
  script_osvdb_id(10547);
  script_xref(name:"DSA", value:"557");

  script_name(english:"Debian DSA-557-1 : rp-pppoe - missing privilege dropping");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Max Vozeler discovered a vulnerability in pppoe, the PPP over Ethernet
driver from Roaring Penguin. When the program is running setuid root
(which is not the case in a default Debian installation), an attacker
could overwrite any file on the file system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-557"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pppoe package.

For the stable distribution (woody) this problem has been fixed in
version 3.3-1.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pppoe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rp-pppoe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/07");
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
if (deb_check(release:"3.0", prefix:"pppoe", reference:"3.3-1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
