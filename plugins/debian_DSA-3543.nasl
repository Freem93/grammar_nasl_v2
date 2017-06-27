#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3543. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90371);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-1235");
  script_osvdb_id(136699);
  script_xref(name:"DSA", value:"3543");

  script_name(english:"Debian DSA-3543-1 : oar - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Emmanuel Thome discovered that missing sanitising in the oarsh command
of OAR, a software used to manage jobs and resources of HPC clusters,
could result in privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/oar"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/oar"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3543"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the oar packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 2.5.2-3+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.5.4-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:oar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"liboar-perl", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-admin", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-api", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-common", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-doc", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-node", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-restful-api", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-server", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-server-mysql", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-server-pgsql", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-user", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-user-mysql", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-user-pgsql", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"oar-web-status", reference:"2.5.2-3+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"liboar-perl", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-api", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-common", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-doc", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-node", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-restful-api", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-server", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-server-mysql", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-server-pgsql", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-user", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-user-mysql", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-user-pgsql", reference:"2.5.4-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"oar-web-status", reference:"2.5.4-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
