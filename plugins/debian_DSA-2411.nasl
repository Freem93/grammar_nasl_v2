#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2411. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58011);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-0863");
  script_bugtraq_id(52024);
  script_osvdb_id(79278);
  script_xref(name:"DSA", value:"2411");

  script_name(english:"Debian DSA-2411-1 : mumble - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Mumble, a VoIP client, does not properly manage
permissions on its user-specific configuration files, allowing other
local users on the system to access them."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=659039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mumble"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2411"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mumble packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.2-6+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mumble");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"mumble", reference:"1.2.2-6+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mumble-11x", reference:"1.2.2-6+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mumble-dbg", reference:"1.2.2-6+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mumble-server", reference:"1.2.2-6+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mumble-server-web", reference:"1.2.2-6+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
