#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1623. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33772);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/04/29 04:40:48 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-4194");
  script_osvdb_id(46776, 46777, 46786, 46836, 46837, 46916, 47232, 47233, 47916, 47926, 47927, 48245);
  script_xref(name:"DSA", value:"1623");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Debian DSA-1623-1 : dnsmasq - DNS cache poisoning");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks. Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting.

This update changes Debian's dnsmasq packages to implement the
recommended countermeasure: UDP query source port randomization. This
change increases the size of the space from which an attacker has to
guess values in a backwards-compatible fashion and makes successful
attacks significantly more difficult.

This update also switches the random number generator to Dan
Bernstein's SURF."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1623"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dnsmasq package.

For the stable distribution (etch), this problem has been fixed in
version 2.35-1+etch4. Packages for alpha will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"4.0", prefix:"dnsmasq", reference:"2.35-1+etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
