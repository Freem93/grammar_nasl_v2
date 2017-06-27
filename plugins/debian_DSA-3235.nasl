#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3235. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83063);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_bugtraq_id(74072, 74097, 74104, 74111, 74119, 74147, 74149);
  script_osvdb_id(15435, 120703, 120709, 120710, 120711, 120712, 120713, 124976);
  script_xref(name:"DSA", value:"3235");

  script_name(english:"Debian DSA-3235-1 : openjdk-7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in the execution
of arbitrary code, breakouts of the Java sandbox, information
disclosure or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openjdk-7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3235"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-7 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 7u79-2.5.5-1~deb7u1.

For the upcoming stable distribution (jessie), these problems will be
fixed soon in version 7u79-2.5.5-1~deb8u1 (the update will be
available shortly after the final jessie release)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
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
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-cacao", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-jamvm", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-dbg", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-demo", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-doc", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jdk", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-headless", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-lib", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-zero", reference:"7u79-2.5.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-source", reference:"7u79-2.5.5-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
