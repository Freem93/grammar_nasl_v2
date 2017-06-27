#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3465. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88568);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_osvdb_id(132305, 133156, 133157, 133159, 133160, 133161);
  script_xref(name:"DSA", value:"3465");

  script_name(english:"Debian DSA-3465-1 : openjdk-6 - security update (SLOTH)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in breakouts of
the Java sandbox, information disclosure, denial of service and
insecure cryptography."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3465"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 6b38-1.13.10-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");
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
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-cacao", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-jamvm", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-dbg", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-demo", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-doc", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jdk", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-headless", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-lib", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-zero", reference:"6b38-1.13.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-source", reference:"6b38-1.13.10-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
