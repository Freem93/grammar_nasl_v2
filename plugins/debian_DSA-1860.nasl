#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1860. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44725);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0642", "CVE-2009-1904");
  script_bugtraq_id(35278);
  script_xref(name:"DSA", value:"1860");

  script_name(english:"Debian DSA-1860-1 : ruby1.8, ruby1.9 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Ruby. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-0642
    The return value from the OCSP_basic_verify function was
    not checked properly, allowing continued use of a
    revoked certificate.

  - CVE-2009-1904
    An issue in parsing BigDecimal numbers can result in a
    denial-of-service condition (crash).

The following matrix identifies fixed versions :

                        ruby1.8                ruby1.9                
  oldstable (etch)       1.8.5-4etch5           1.9.0+20060609-1etch5  
  stable (lenny)         1.8.7.72-3lenny1       1.9.0.2-9lenny1        
  unstable (sid)         1.8.7.173-1            (soon)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1860"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the Ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
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
if (deb_check(release:"4.0", prefix:"irb1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"irb1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.8-dbg", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9-dbg", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-dev", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-elisp", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-examples", reference:"1.8.5-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-dev", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-elisp", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-examples", reference:"1.9.0+20060609-1etch5")) flag++;
if (deb_check(release:"5.0", prefix:"irb1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"irb1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libdbm-ruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libdbm-ruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgdbm-ruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgdbm-ruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libopenssl-ruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libopenssl-ruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libreadline-ruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libreadline-ruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libruby1.8-dbg", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libruby1.9-dbg", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libtcltk-ruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libtcltk-ruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"rdoc1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"rdoc1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ri1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ri1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.8", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.8-dev", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.8-elisp", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.8-examples", reference:"1.8.7.72-3lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.9", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.9-dev", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.9-elisp", reference:"1.9.0.2-9lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ruby1.9-examples", reference:"1.9.0.2-9lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
