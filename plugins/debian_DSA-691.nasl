#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-691. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17286);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/06/02 14:01:26 $");

  script_cve_id("CVE-2005-0098", "CVE-2005-0099");
  script_osvdb_id(14609, 14610);
  script_xref(name:"DSA", value:"691");

  script_name(english:"Debian DSA-691-1 : abuse - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in abuse, the SDL port of
the Abuse action game. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CAN-2005-0098
    Erik Sjolund discovered several buffer overflows in the
    command line handling, which could lead to the execution
    of arbitrary code with elevated privileges since it is
    installed setuid root.

  - CAN-2005-0099

    Steve Kemp discovered that abuse creates some files
    without dropping privileges first, which may lead to the
    creation and overwriting of arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-691"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the abuse package.

For the stable distribution (woody) these problems have been fixed in
version 2.00+-3woody4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:abuse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"abuse", reference:"2.00+-3woody4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
