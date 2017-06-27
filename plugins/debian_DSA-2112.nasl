#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2112. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49291);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/29 04:40:48 $");

  script_cve_id("CVE-2010-0405");
  script_osvdb_id(68167);
  script_xref(name:"DSA", value:"2112");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"Debian DSA-2112-1 : bzip2 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mikolaj Izdebski has discovered an integer overflow flaw in the
BZ2_decompress function in bzip2/libbz2. An attacker could use a
crafted bz2 file to cause a denial of service (application crash) or
potentially to execute arbitrary code. (CVE-2010-0405 )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2112"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bzip2 / dpkg packages.

After the upgrade, all running services that use libbz2 need to be
restarted.

This update also provides rebuilt dpkg packages, which are statically
linked to the fixed version of libbz2. Updated packages for clamav,
which is also affected by this issue, will be provided on
debian-volatile.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.5-1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"bzip2", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bzip2-doc", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dpkg", reference:"1.14.29+b1")) flag++;
if (deb_check(release:"5.0", prefix:"dselect", reference:"1.14.29+b1")) flag++;
if (deb_check(release:"5.0", prefix:"lib32bz2-1.0", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lib32bz2-dev", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lib64bz2-1.0", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lib64bz2-dev", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libbz2-1.0", reference:"1.0.5-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libbz2-dev", reference:"1.0.5-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
