#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3357. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85913);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/09/30 13:50:19 $");

  script_cve_id("CVE-2015-6927");
  script_osvdb_id(127459);
  script_xref(name:"DSA", value:"3357");

  script_name(english:"Debian DSA-3357-1 : vzctl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that vzctl, a set of control tools for the OpenVZ
server virtualisation solution, determined the storage layout of
containers based on the presence of an XML file inside the container.
An attacker with local root privileges in a simfs-based container
could gain control over ploop-based containers. Further information on
the prerequisites of such an attack can be found at src.openvz.org.

The oldstable distribution (wheezy) is not affected."
  );
  # https://src.openvz.org/projects/OVZL/repos/vzctl/commits/9e98ea630ac0e88b44e3e23c878a5166aeb74e1c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37c93151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/vzctl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3357"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vzctl packages.

For the stable distribution (jessie), this problem has been fixed in
version 4.8-1+deb8u2. During the update existing configurations are
automatically updated."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vzctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"vzctl", reference:"4.8-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
