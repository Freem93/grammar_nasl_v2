#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-814. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19710);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2672");
  script_osvdb_id(18905);
  script_xref(name:"DSA", value:"814");

  script_name(english:"Debian DSA-814-1 : lm-sensors - insecure temporary file");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena discovered that a script of
lm-sensors, utilities to read temperature/voltage/fan sensors, creates
a temporary file with a predictable filename, leaving it vulnerable
for a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=324193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-814"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lm-sensors package.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 2.9.1-1sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lm-sensors");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4-lm-sensors", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsensors-dev", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsensors3", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-386", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-586tsc", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-686", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-686-smp", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-k6", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-k7", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-2-k7-smp", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-source", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sensord", reference:"2.9.1-1sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
