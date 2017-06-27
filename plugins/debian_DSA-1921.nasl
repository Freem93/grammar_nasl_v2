#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1921. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44786);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-2625");
  script_bugtraq_id(35958);
  script_osvdb_id(56984);
  script_xref(name:"DSA", value:"1921");

  script_name(english:"Debian DSA-1921-1 : expat - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Peter Valchev discovered an error in expat, an XML parsing C library,
when parsing certain UTF-8 sequences, which can be exploited to crash
an application using the library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=551936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1921"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the expat packages.

For the old stable distribution (etch), this problem has been fixed in
version 1.95.8-3.4+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 2.0.1-4+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"expat", reference:"1.95.8-3.4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libexpat1", reference:"1.95.8-3.4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libexpat1-dev", reference:"1.95.8-3.4+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"expat", reference:"2.0.1-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lib64expat1", reference:"2.0.1-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lib64expat1-dev", reference:"2.0.1-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libexpat1", reference:"2.0.1-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libexpat1-dev", reference:"2.0.1-4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
