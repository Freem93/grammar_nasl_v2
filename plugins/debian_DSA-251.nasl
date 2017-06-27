#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-251. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15088);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:07:13 $");

  script_cve_id("CVE-2002-1335", "CVE-2002-1348");
  script_osvdb_id(6981);
  script_xref(name:"DSA", value:"251");

  script_name(english:"Debian DSA-251-1 : w3m - missing HTML quoting");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hironori Sakamoto, one of the w3m developers, found two security
vulnerabilities in w3m and associated programs. The w3m browser does
not properly escape HTML tags in frame contents and img alt
attributes. A malicious HTML frame or img alt attribute may deceive a
user to send their local cookies which are used for configuration. The
information is not leaked automatically, though."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the w3m and w3m-ssl packages.

For the stable distribution (woody) these problems have been fixed in
version 0.3-2.4.

The old stable distribution (potato) is not affected by these
problems."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:w3m-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"w3m", reference:"0.3-2.4")) flag++;
if (deb_check(release:"3.0", prefix:"w3m-img", reference:"0.3-2.4")) flag++;
if (deb_check(release:"3.0", prefix:"w3m-ssl", reference:"0.3-2.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
