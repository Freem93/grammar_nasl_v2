#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3651. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93114);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-6316");
  script_osvdb_id(142874);
  script_xref(name:"DSA", value:"3651");

  script_name(english:"Debian DSA-3651-1 : rails - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrew Carpenter of Critical Juncture discovered a cross-site
scripting vulnerability affecting Action View in rails, a web
application framework written in Ruby. Text declared as 'HTML safe'
will not have quotes escaped when used as attribute values in tag
helpers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=834155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/rails"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3651"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rails packages.

For the stable distribution (jessie), this problem has been fixed in
version 2:4.1.8-1+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"rails", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionmailer", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionpack", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionview", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activemodel", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activerecord", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport-2.3", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-rails", reference:"2:4.1.8-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-railties", reference:"2:4.1.8-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
