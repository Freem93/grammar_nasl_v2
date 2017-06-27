#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-265. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15102);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2003-0152", "CVE-2003-0153", "CVE-2003-0154", "CVE-2003-0155");
  script_osvdb_id(5457, 5458, 5459, 5460, 5461, 5462, 5463, 5464, 5465, 5634);
  script_xref(name:"DSA", value:"265");

  script_name(english:"Debian DSA-265-1 : bonsai - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Remi Perrot fixed several security related bugs in the bonsai, the
Mozilla CVS query tool by web interface. Vulnerabilities include
arbitrary code execution, cross-site scripting and access to
configuration parameters. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CAN-2003-0152 - Remote execution of arbitrary commands
    as www-data
  - CAN-2003-0153 - Absolute path disclosure

  - CAN-2003-0154 - Cross site scripting attacks 

  - CAN-2003-0155 - Unauthenticated access to parameters
    page"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-265"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bonsai package.

For the stable distribution (woody) these problems have been fixed in
version 1.3+cvs20020224-1woody1.


The old stable distribution (potato) is not affected since it doesn't
contain bonsai."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bonsai");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"bonsai", reference:"1.3+cvs20020224-1woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
