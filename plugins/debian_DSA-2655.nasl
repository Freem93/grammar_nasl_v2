#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2655. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65727);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:37:40 $");

  script_cve_id("CVE-2011-2932", "CVE-2012-3464", "CVE-2012-3465", "CVE-2013-1854", "CVE-2013-1855", "CVE-2013-1857");
  script_bugtraq_id(54957, 54958, 58549, 58552, 58555);
  script_osvdb_id(74618, 84513, 84516, 91452, 91453, 91454);
  script_xref(name:"DSA", value:"2655");

  script_name(english:"Debian DSA-2655-1 : rails - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several cross-site-scripting and denial of service vulnerabilities
were discovered in Ruby on Rails, a Ruby framework for web application
development."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/rails"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2655"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rails packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.3.5-1.2+squeeze8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libactionmailer-ruby", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactionmailer-ruby1.8", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactionpack-ruby", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactionpack-ruby1.8", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby1.8", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby1.9.1", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactiveresource-ruby", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactiveresource-ruby1.8", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby1.8", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby1.9.1", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rails", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rails-doc", reference:"2.3.5-1.2+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rails-ruby1.8", reference:"2.3.5-1.2+squeeze8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
