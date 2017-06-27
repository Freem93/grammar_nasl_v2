#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2806. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71141);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-6410");
  script_bugtraq_id(64002);
  script_osvdb_id(100407);
  script_xref(name:"DSA", value:"2806");

  script_name(english:"Debian DSA-2806-1 : nbd - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that nbd-server, the server for the Network Block
Device protocol, did incorrect parsing of the access control lists,
allowing access to any hosts with an IP address sharing a prefix with
an allowed address."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/nbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2806"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nbd packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1:2.9.16-8+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1:3.2-4~deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"nbd-client", reference:"1:2.9.16-8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"nbd-client-udeb", reference:"1:2.9.16-8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"nbd-server", reference:"1:2.9.16-8+squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"nbd-client", reference:"1:3.2-4~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"nbd-client-udeb", reference:"1:3.2-4~deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"nbd-server", reference:"1:3.2-4~deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
