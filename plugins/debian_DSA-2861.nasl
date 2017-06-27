#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2861. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72537);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2014-1943");
  script_osvdb_id(103424);
  script_xref(name:"DSA", value:"2861");

  script_name(english:"Debian DSA-2861-1 : file - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that file, a file type classification tool, contains
a flaw in the handling of 'indirect' magic rules in the libmagic
library, which leads to an infinite recursion when trying to determine
the file type of certain files. The Common Vulnerabilities and
Exposures project ID CVE-2014-1943 has been assigned to identify this
flaw. Additionally, other well-crafted files might result in long
computation times (while using 100% CPU) and overlong results."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=738832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2861"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the file packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 5.04-5+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 5.11-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:file");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"file", reference:"5.04-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagic-dev", reference:"5.04-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagic1", reference:"5.04-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"python-magic", reference:"5.04-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"python-magic-dbg", reference:"5.04-5+squeeze3")) flag++;
if (deb_check(release:"7.0", prefix:"file", reference:"5.11-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmagic-dev", reference:"5.11-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmagic1", reference:"5.11-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-magic", reference:"5.11-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-magic-dbg", reference:"5.11-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
