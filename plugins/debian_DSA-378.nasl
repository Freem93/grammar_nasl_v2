#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-378. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15215);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:11:34 $");

  script_cve_id("CVE-2003-0705", "CVE-2003-0706");
  script_bugtraq_id(8557, 8558);
  script_osvdb_id(6586, 6587);
  script_xref(name:"DSA", value:"378");

  script_name(english:"Debian DSA-378-1 : mah-jong - buffer overflows, denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nicolas Boullis discovered two vulnerabilities in mah-jong, a
network-enabled game.

  - CAN-2003-0705 (buffer overflow)
    This vulnerability could be exploited by a remote
    attacker to execute arbitrary code with the privileges
    of the user running the mah-jong server.

  - CAN-2003-0706 (denial of service)

    This vulnerability could be exploited by a remote
    attacker to cause the mah-jong server to enter a tight
    loop and stop responding to commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
version 1.4-2.

We recommend that you update your mah-jong package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mah-jong");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/07");
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
if (deb_check(release:"3.0", prefix:"mah-jong", reference:"1.4-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
