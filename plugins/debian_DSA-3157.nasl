#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3157. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81250);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/03 13:42:51 $");

  script_cve_id("CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090");
  script_bugtraq_id(68474, 70935, 71230);
  script_osvdb_id(108971, 113747, 114641);
  script_xref(name:"DSA", value:"3157");

  script_name(english:"Debian DSA-3157-1 : ruby1.9.1 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the interpreter for the
Ruby language :

  - CVE-2014-4975
    The encodes() function in pack.c had an off-by-one error
    that could lead to a stack-based buffer overflow. This
    could allow remote attackers to cause a denial of
    service (crash) or arbitrary code execution.

  - CVE-2014-8080, CVE-2014-8090
    The REXML parser could be coerced into allocating large
    string objects that could consume all available memory
    on the system. This could allow remote attackers to
    cause a denial of service (crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby1.9.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3157"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.9.1 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.9.3.194-8.1+deb7u3.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 2.1.5-1 of the ruby2.1 source package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libruby1.9.1", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.9.1-dbg", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libtcltk-ruby1.9.1", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ri1.9.1", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-dev", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-examples", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-full", reference:"1.9.3.194-8.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.3", reference:"1.9.3.194-8.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
