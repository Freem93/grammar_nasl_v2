#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2664. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66296);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/02/16 15:37:40 $");

  script_cve_id("CVE-2013-1762");
  script_bugtraq_id(58277);
  script_xref(name:"DSA", value:"2664");

  script_name(english:"Debian DSA-2664-1 : stunnel4 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stunnel, a program designed to work as an universal SSL tunnel for
network daemons, is prone to a buffer overflow vulnerability when
using the Microsoft NT LAN Manager (NTLM) authentication
('protocolAuthentication = NTLM') together with the 'connect'protocol
method ('protocol = connect'). With these prerequisites and using
stunnel4 in SSL client mode ('client = yes') on a 64 bit host, an
attacker could possibly execute arbitrary code with the privileges of
the stunnel process, if the attacker can either control the specified
proxy server or perform man-in-the-middle attacks on the tcp session
between stunnel and the proxy sever.

Note that for the testing distribution (wheezy) and the unstable
distribution (sid), stunnel4 is compiled with stack smashing
protection enabled, which should help protect against arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/stunnel4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2664"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the stunnel4 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3:4.29-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:stunnel4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"stunnel", reference:"3:4.29-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"stunnel4", reference:"3:4.29-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
