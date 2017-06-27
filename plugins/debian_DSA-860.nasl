#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-860. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19968);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2337");
  script_osvdb_id(19610);
  script_xref(name:"CERT", value:"160012");
  script_xref(name:"DSA", value:"860");

  script_name(english:"Debian DSA-860-1 : ruby - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Yutaka Oiwa discovered a bug in Ruby, the interpreter for the
object-oriented scripting language, that can cause illegal program
code to bypass the safe level and taint flag protections check and be
executed. The following matrix lists the fixed versions in our
distributions :

                      old stable (woody)  stable (sarge)      unstable (sid)      
  ruby                1.6.7-3woody5       n/a                 n/a                 
  ruby1.6             n/a                 1.6.8-12sarge1      1.6.8-13            
  ruby1.8             n/a                 1.8.2-7sarge2       1.8.3-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=332742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-860"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/22");
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
if (deb_check(release:"3.0", prefix:"irb", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libcurses-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libdbm-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libgdbm-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libnkf-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libpty-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libreadline-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libsdbm-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libsyslog-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libtcltk-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libtk-ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"ruby", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-dev", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-elisp", reference:"1.6.7-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-examples", reference:"1.6.7-3woody5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
