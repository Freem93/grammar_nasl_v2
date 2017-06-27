#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3168. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81447);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/02/24 14:41:20 $");

  script_cve_id("CVE-2012-6684");
  script_xref(name:"DSA", value:"3168");

  script_name(english:"Debian DSA-3168-1 : ruby-redcloth - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kousuke Ebihara discovered that redcloth, a Ruby module used to
convert Textile markup to HTML, did not properly sanitize its input.
This allowed a remote attacker to perform a cross-site scripting
attack by injecting arbitrary JavaScript code into the generated HTML."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=774748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby-redcloth"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3168"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby-redcloth packages.

For the stable distribution (wheezy), this problem has been fixed in
version 4.2.9-2+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-redcloth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libredcloth-ruby", reference:"4.2.9-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libredcloth-ruby-doc", reference:"4.2.9-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libredcloth-ruby1.8", reference:"4.2.9-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libredcloth-ruby1.9.1", reference:"4.2.9-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ruby-redcloth", reference:"4.2.9-2+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
