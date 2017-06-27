#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2604. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63457);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2013-0156");
  script_bugtraq_id(57187);
  script_osvdb_id(89026);
  script_xref(name:"DSA", value:"2604");

  script_name(english:"Debian DSA-2604-1 : rails - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Rails, the Ruby web application development
framework, performed insufficient validation on input parameters,
allowing unintended type conversions. An attacker may use this to
bypass authentication systems, inject arbitrary SQL, inject and
execute arbitrary code, or perform a DoS attack on the application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=697722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/rails"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2604"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rails packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze4.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails XML Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/10");
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
if (deb_check(release:"6.0", prefix:"libactionmailer-ruby", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactionmailer-ruby1.8", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactionpack-ruby", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactionpack-ruby1.8", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby1.8", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactiverecord-ruby1.9.1", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactiveresource-ruby", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactiveresource-ruby1.8", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby1.8", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"libactivesupport-ruby1.9.1", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"rails", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"rails-doc", reference:"2.3.5-1.2+squeeze4.1")) flag++;
if (deb_check(release:"6.0", prefix:"rails-ruby1.8", reference:"2.3.5-1.2+squeeze4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
