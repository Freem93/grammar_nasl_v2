#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2206. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53211);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-0439", "CVE-2011-0440");
  script_bugtraq_id(47033);
  script_osvdb_id(72154, 72155);
  script_xref(name:"DSA", value:"2206");

  script_name(english:"Debian DSA-2206-1 : mahara - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities have been discovered in Mahara, a fully
featured electronic portfolio, weblog, resume builder and social
networking system :

  - CVE-2011-0439
    A security review commissioned by a Mahara user
    discovered that Mahara processes unsanitized input which
    can lead to cross-site scripting (XSS).

  - CVE-2011-0440
    Mahara Developers discovered that Mahara doesn't check
    the session key under certain circumstances which can be
    exploited as cross-site request forgery (CSRF) and can
    lead to the deletion of blogs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mahara"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2206"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mahara package.

For the old stable distribution (lenny) these problems have been fixed
in version 1.0.4-4+lenny8.

For the stable distribution (squeeze) these problems have been fixed
in version 1.2.6-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mahara");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mahara", reference:"1.0.4-4+lenny8")) flag++;
if (deb_check(release:"6.0", prefix:"mahara", reference:"1.2.6-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-apache2", reference:"1.2.6-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-mediaplayer", reference:"1.2.6-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
