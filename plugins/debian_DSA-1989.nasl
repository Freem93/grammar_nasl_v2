#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1989. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44853);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:40 $");

  script_cve_id("CVE-2010-0789");
  script_bugtraq_id(37983);
  script_xref(name:"DSA", value:"1989");

  script_name(english:"Debian DSA-1989-1 : fuse - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Rosenberg discovered a race condition in FUSE, a Filesystem in
USErspace. A local attacker, with access to use FUSE, could unmount
arbitrary locations, leading to a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=567633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1989"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fuse packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.5.3-4.4+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 2.7.4-1.1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"4.0", prefix:"fuse-utils", reference:"2.5.3-4.4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libfuse-dev", reference:"2.5.3-4.4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libfuse2", reference:"2.5.3-4.4+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"fuse-utils", reference:"2.7.4-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libfuse-dev", reference:"2.7.4-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libfuse2", reference:"2.7.4-1.1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
