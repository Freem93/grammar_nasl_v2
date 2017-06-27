#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2982. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76605);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2014-3482", "CVE-2014-3483");
  script_bugtraq_id(68341, 68343);
  script_xref(name:"DSA", value:"2982");

  script_name(english:"Debian DSA-2982-1 : ruby-activerecord-3.2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sean Griffin discovered two vulnerabilities in the PostgreSQL adapter
for Active Record which could lead to SQL injection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby-activerecord-3.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2982"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby-activerecord-3.2 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.2.6-5+deb7u1. Debian provides two variants of 'Ruby on
Rails' in Wheezy (2.3 and 3.2). Support for the 2.3 variants had to be
ceased at this point. This affects the following source packages:
ruby-actionmailer-2.3, ruby-actionpack-2.3, ruby-activerecord-2.3,
ruby-activeresource-2.3, ruby-activesupport-2.3 and ruby-rails-2.3.
The version of Redmine in Wheezy still requires 2.3, you can use an
updated version from backports.debian.org which is compatible with
rails 3.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activerecord-3.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ruby-activerecord-3.2", reference:"3.2.6-5+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
