#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1170. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22712);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2006-3619");
  script_bugtraq_id(15669);
  script_osvdb_id(27380);
  script_xref(name:"DSA", value:"1170");

  script_name(english:"Debian DSA-1170-1 : gcc-3.4 - missing sanity check");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jurgen Weigert discovered that upon unpacking JAR archives fastjar
from the GNU Compiler Collection does not check the path for included
files and allows to create or overwrite files in upper directories."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=368397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1170"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fastjar package.

For the stable distribution (sarge) this problem has been fixed in
version 3.4.3-13sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gcc-3.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"cpp-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"cpp-3.4-doc", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"fastjar", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"g++-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"g77-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"g77-3.4-doc", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gcc-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gcc-3.4-base", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gcc-3.4-doc", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gcc-3.4-hppa64", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gcj-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gij-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnat-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnat-3.4-doc", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gobjc-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gpc-2.1-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gpc-2.1-3.4-doc", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lib32gcc1", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lib32stdc++6", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lib64gcc1", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lib64stdc++6", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libffi3", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libffi3-dev", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgcc1", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgcc2", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgcj5", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgcj5-awt", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgcj5-common", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgcj5-dev", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgnat-3.4", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-0", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-0-dbg", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-0-dev", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-0-pic", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-dbg", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-dev", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-doc", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstdc++6-pic", reference:"3.4.3-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"treelang-3.4", reference:"3.4.3-13sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
