#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3749. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96193);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/02/28 14:42:19 $");

  script_cve_id("CVE-2015-8979");
  script_osvdb_id(149181);
  script_xref(name:"DSA", value:"3749");

  script_name(english:"Debian DSA-3749-1 : dcmtk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gjoko Krstic of Zero Science Labs discovered that dcmtk, a collection
of libraries implementing the DICOM standard, did not properly handle
the size of data received from the network. This could lead to
denial-of-service (via application crash) or arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=848830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/dcmtk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3749"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dcmtk packages.

For the stable distribution (jessie), this problem has been fixed in
version 3.6.0-15+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dcmtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"dcmtk", reference:"3.6.0-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"dcmtk-doc", reference:"3.6.0-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"dcmtk-www", reference:"3.6.0-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libdcmtk2", reference:"3.6.0-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libdcmtk2-dbg", reference:"3.6.0-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libdcmtk2-dev", reference:"3.6.0-15+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
