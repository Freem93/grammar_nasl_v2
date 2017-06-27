#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3271. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83788);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2013-7441", "CVE-2015-0847");
  script_bugtraq_id(74557);
  script_osvdb_id(121822, 122980);
  script_xref(name:"DSA", value:"3271");

  script_name(english:"Debian DSA-3271-1 : nbd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tuomas Rasanen discovered that unsafe signal handling in nbd-server,
the server for the Network Block Device protocol, could allow remote
attackers to cause a deadlock in the server process and thus a denial
of service.

Tuomas Rasanen also discovered that the modern-style negotiation was
carried out in the main server process before forking the actual
client handler. This could allow a remote attacker to cause a denial
of service (crash) by querying a non-existent export. This issue only
affected the oldstable distribution (wheezy)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=781547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=784657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3271"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nbd packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1:3.2-4~deb7u5.

For the stable distribution (jessie), these problems have been fixed
in version 1:3.8-4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"nbd-client", reference:"1:3.2-4~deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"nbd-client-udeb", reference:"1:3.2-4~deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"nbd-server", reference:"1:3.2-4~deb7u5")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-client", reference:"1:3.8-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-client-udeb", reference:"1:3.8-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-server", reference:"1:3.8-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
