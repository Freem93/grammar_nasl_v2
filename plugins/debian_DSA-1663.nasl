#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1663. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34720);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");
  script_bugtraq_id(29212, 29623, 32020);
  script_xref(name:"DSA", value:"1663");

  script_name(english:"Debian DSA-1663-1 : net-snmp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in NET SNMP, a suite of
Simple Network Management Protocol applications. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-0960
    Wes Hardaker reported that the SNMPv3 HMAC verification
    relies on the client to specify the HMAC length, which
    allows spoofing of authenticated SNMPv3 packets.

  - CVE-2008-2292
    John Kortink reported a buffer overflow in the
    __snprint_value function in snmp_get causing a denial of
    service and potentially allowing the execution of
    arbitrary code via a large OCTETSTRING in an attribute
    value pair (AVP).

  - CVE-2008-4309
    It was reported that an integer overflow in the
    netsnmp_create_subtree_cache function in
    agent/snmp_agent.c allows remote attackers to cause a
    denial of service attack via a crafted SNMP GETBULK
    request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=485945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=482333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1663"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the net-snmp package.

For the stable distribution (etch), these problems has been fixed in
version 5.2.3-7etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libsnmp-base", reference:"5.2.3-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libsnmp-perl", reference:"5.2.3-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libsnmp9", reference:"5.2.3-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libsnmp9-dev", reference:"5.2.3-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"snmp", reference:"5.2.3-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"snmpd", reference:"5.2.3-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"tkmib", reference:"5.2.3-7etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
