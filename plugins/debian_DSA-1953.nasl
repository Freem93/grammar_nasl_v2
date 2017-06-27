#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1953. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44818);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/01/27 00:45:19 $");

  script_cve_id("CVE-2009-3560");
  script_bugtraq_id(37203);
  script_osvdb_id(60797);
  script_xref(name:"DSA", value:"1953");

  script_name(english:"Debian DSA-1953-1 : expat - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jan Lieskovsky discovered an error in expat, an XML parsing C library,
when parsing certain UTF-8 sequences, which can be exploited to crash
an application using the library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=560901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1953"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the expat packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.95.8-3.4+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 2.0.1-4+lenny2.

The builds for the mipsel architecture for the oldstable distribution
are not included yet. They will be released when they become
available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"expat", reference:"1.95.8-3.4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libexpat1", reference:"1.95.8-3.4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libexpat1-dev", reference:"1.95.8-3.4+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"expat", reference:"2.0.1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"lib64expat1", reference:"2.0.1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"lib64expat1-dev", reference:"2.0.1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libexpat1", reference:"2.0.1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libexpat1-dev", reference:"2.0.1-4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
