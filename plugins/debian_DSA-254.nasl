#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-254. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15091);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:07:13 $");

  script_cve_id("CVE-2002-1051", "CVE-2002-1364", "CVE-2002-1386", "CVE-2002-1387");
  script_bugtraq_id(4956, 6166, 6274, 6275);
  script_xref(name:"DSA", value:"254");

  script_name(english:"Debian DSA-254-1 : traceroute-nanog - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in NANOG traceroute, an enhanced
version of the Van Jacobson/BSD traceroute program. A buffer overflow
occurs in the 'get_origin()' function. Due to insufficient bounds
checking performed by the whois parser, it may be possible to corrupt
memory on the system stack. This vulnerability can be exploited by a
remote attacker to gain root privileges on a target host. Though, most
probably not in Debian.

The Common Vulnerabilities and Exposures (CVE) project additionally
identified the following vulnerabilities which were already fixed in
the Debian version in stable (woody) and oldstable (potato) and are
mentioned here for completeness (and since other distributions had to
release a separate advisory for them) :

  - CAN-2002-1364 (BugTraq ID 6166) talks about a buffer
    overflow in the get_origin function which allows
    attackers to execute arbitrary code via long WHOIS
    responses.
  - CAN-2002-1051 (BugTraq ID 4956) talks about a format
    string vulnerability that allows local users to execute
    arbitrary code via the -T (terminator) command line
    argument.

  - CAN-2002-1386 talks about a buffer overflow that may
    allow local users to execute arbitrary code via a long
    hostname argument.

  - CAN-2002-1387 talks about the spray mode that may allow
    local users to overwrite arbitrary memory locations.

Fortunately, the Debian package drops privileges quite early after
startup, so those problems are not likely to result in an exploit on a
Debian machine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-254"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the traceroute-nanog package.

For the current stable distribution (woody) the above problem has been
fixed in version 6.1.1-1.2.

For the old stable distribution (potato) the above problem has been
fixed in version 6.0-2.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:traceroute-nanog");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"traceroute-nanog", reference:"6.0-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"traceroute-nanog", reference:"6.1.1-1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
