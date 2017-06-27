#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2827. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71618);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/09/01 13:14:18 $");

  script_cve_id("CVE-2013-2186");
  script_bugtraq_id(63174);
  script_xref(name:"DSA", value:"2827");
  script_xref(name:"TRA", value:"TRA-2016-23");

  script_name(english:"Debian DSA-2827-1 : libcommons-fileupload-java - arbitrary file upload via deserialization");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Apache Commons FileUpload, a package to make it
easy to add robust, high-performance, file upload capability to
servlets and web applications, incorrectly handled file names with
NULL bytes in serialized instances. A remote attacker able to supply a
serialized instance of the DiskFileItem class, which will be
deserialized on a server, could use this flaw to write arbitrary
content to any location on the server that is accessible to the user
running the application server process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=726601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libcommons-fileupload-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libcommons-fileupload-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2016-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libcommons-fileupload-java packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.2.2-1+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.2.2-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcommons-fileupload-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libcommons-fileupload-java", reference:"1.2.2-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libcommons-fileupload-java-doc", reference:"1.2.2-1+deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"libcommons-fileupload-java", reference:"1.2.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libcommons-fileupload-java-doc", reference:"1.2.2-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
