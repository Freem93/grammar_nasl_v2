#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1626. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33775);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:49:54 $");

  script_cve_id("CVE-2008-3429");
  script_bugtraq_id(30425);
  script_xref(name:"DSA", value:"1626");

  script_name(english:"Debian DSA-1626-1 : httrack - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joan Calvet discovered that httrack, a utility to create local copies
of websites, is vulnerable to a buffer overflow potentially allowing
to execute arbitrary code when passed excessively long URLs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the httrack package.

For the stable distribution (etch), this problem has been fixed in
version 3.40.4-3.1+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:httrack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"httrack", reference:"3.40.4-3.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"httrack-doc", reference:"3.40.4-3.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libhttrack-dev", reference:"3.40.4-3.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libhttrack1", reference:"3.40.4-3.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"proxytrack", reference:"3.40.4-3.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"webhttrack", reference:"3.40.4-3.1+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
