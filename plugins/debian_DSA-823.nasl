#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-823. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19792);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2876");
  script_osvdb_id(19369);
  script_xref(name:"DSA", value:"823");

  script_name(english:"Debian DSA-823-1 : util-linux - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"David Watson discovered a bug in mount as provided by util-linux and
other packages such as loop-aes-utils that allows local users to
bypass filesystem access restrictions by re-mounting it read-only."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=328141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=329063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-823"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the util-linux package.

For the old stable distribution (woody) this problem has been fixed in
version 2.11n-7woody1.

For the stable distribution (sarge) this problem has been fixed in
version 2.12p-4sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"bsdutils", reference:"2.11n-7woody1")) flag++;
if (deb_check(release:"3.0", prefix:"mount", reference:"2.11n-7woody1")) flag++;
if (deb_check(release:"3.0", prefix:"util-linux", reference:"2.11n-7woody1")) flag++;
if (deb_check(release:"3.0", prefix:"util-linux-locales", reference:"2.11n-7woody1")) flag++;
if (deb_check(release:"3.1", prefix:"bsdutils", reference:"2.12p-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mount", reference:"2.12p-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"util-linux", reference:"2.12p-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"util-linux-locales", reference:"2.12p-4sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
