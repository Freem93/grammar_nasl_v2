#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3199. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81983);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/14 13:43:55 $");

  script_cve_id("CVE-2015-0252");
  script_bugtraq_id(73252);
  script_osvdb_id(119811);
  script_xref(name:"DSA", value:"3199");

  script_name(english:"Debian DSA-3199-1 : xerces-c - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Anton Rager and Jonathan Brossard from the Salesforce.com Product
Security Team and Ben Laurie of Google discovered a denial of service
vulnerability in xerces-c, a validating XML parser library for C++.
The parser mishandles certain kinds of malformed input documents,
resulting in a segmentation fault during a parse operation. An
unauthenticated attacker could use this flaw to cause an application
using the xerces-c library to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=780827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xerces-c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3199"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xerces-c packages.

For the stable distribution (wheezy), this problem has been fixed in
version 3.1.1-3+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xerces-c");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/23");
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
if (deb_check(release:"7.0", prefix:"libxerces-c-dev", reference:"3.1.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxerces-c-doc", reference:"3.1.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxerces-c-samples", reference:"3.1.1-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxerces-c3.1", reference:"3.1.1-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
