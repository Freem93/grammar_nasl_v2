#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-762. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19225);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-2250", "CVE-2005-2277");
  script_bugtraq_id(14230);
  script_osvdb_id(17852, 17853);
  script_xref(name:"DSA", value:"762");

  script_name(english:"Debian DSA-762-1 : affix - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kevin Finisterre discovered two problems in the Bluetooth FTP client
from affix, user space utilities for the Affix Bluetooth protocol
stack. The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities :

  - CAN-2005-2250
    A buffer overflow allows remote attackers to execute
    arbitrary code via a long filename in an OBEX file
    share.

  - CAN-2005-2277

    Missing input sanitising before executing shell commands
    allow an attacker to execute arbitrary commands as root."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=318327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=318328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-762"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the affix package.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in
version 2.1.1-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/12");
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
if (deb_check(release:"3.1", prefix:"affix", reference:"2.1.1-2")) flag++;
if (deb_check(release:"3.1", prefix:"libaffix-dev", reference:"2.1.1-2")) flag++;
if (deb_check(release:"3.1", prefix:"libaffix2", reference:"2.1.1-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
