#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3727. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95414);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/14 14:43:07 $");

  script_cve_id("CVE-2016-4330", "CVE-2016-4331", "CVE-2016-4332", "CVE-2016-4333");
  script_osvdb_id(147492, 147493, 147494, 147495);
  script_xref(name:"DSA", value:"3727");

  script_name(english:"Debian DSA-3727-1 : hdf5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco Talos discovered that hdf5, a file format and library for
storing scientific data, contained several vulnerabilities that could
lead to arbitrary code execution when handling untrusted data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=845301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/hdf5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3727"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the hdf5 packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.8.13+docs-15+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hdf5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");
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
if (deb_check(release:"8.0", prefix:"hdf5-helpers", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hdf5-tools", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-8", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-8-dbg", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-cpp-8", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-cpp-8-dbg", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-dev", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-doc", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-mpi-dev", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-mpich-8", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-mpich-8-dbg", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-mpich-dev", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-mpich2-dev", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-openmpi-8", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-openmpi-8-dbg", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-openmpi-dev", reference:"1.8.13+docs-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libhdf5-serial-dev", reference:"1.8.13+docs-15+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
