#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1958. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44823);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/19 11:21:00 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"DSA", value:"1958");

  script_name(english:"Debian DSA-1958-1 : libtool - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ltdl, a system-independent dlopen wrapper for
GNU libtool, can be tricked to load and run modules from an arbitrary
directory, which might be used to execute arbitrary code with the
privileges of the user running an application that uses libltdl."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1958"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtool packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.5.22-4+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 1.5.26-4+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libltdl3", reference:"1.5.22-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libltdl3-dev", reference:"1.5.22-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libtool", reference:"1.5.22-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libtool-doc", reference:"1.5.22-4+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libltdl3", reference:"1.5.26-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libltdl3-dev", reference:"1.5.26-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libtool", reference:"1.5.26-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libtool-doc", reference:"1.5.26-4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
