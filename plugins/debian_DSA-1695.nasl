#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1695. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35294);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2008-3443");
  script_bugtraq_id(30682);
  script_xref(name:"DSA", value:"1695");

  script_name(english:"Debian DSA-1695-1 : ruby1.8, ruby1.9 - memory leak");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The regular expression engine of Ruby, a scripting language, contains
a memory leak which can be triggered remotely under certain
circumstances, leading to a denial of service condition (CVE-2008-3443
).

In addition, this security update addresses a regression in the REXML
XML parser of the ruby1.8 package; the regression was introduced in
DSA-1651-1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=494401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1695"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Ruby packages.

For the stable distribution (etch), this problem has been fixed in
version 1.8.5-4etch4 of the ruby1.8 package, and version
1.9.0+20060609-1etch4 of the ruby1.9 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"irb1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"irb1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.8-dbg", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9-dbg", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-dev", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-elisp", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-examples", reference:"1.8.5-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-dev", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-elisp", reference:"1.9.0+20060609-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-examples", reference:"1.9.0+20060609-1etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
