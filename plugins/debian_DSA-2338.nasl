#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2338. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56728);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_bugtraq_id(50283);
  script_osvdb_id(76682, 76683, 76684, 76685, 76686, 76687, 76688, 76689, 76690, 76691, 76692, 76693, 76694, 76695, 76696);
  script_xref(name:"DSA", value:"2338");

  script_name(english:"Debian DSA-2338-1 : moodle - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several cross-site scripting and information disclosure issues have
been fixed in Moodle, a course management system for online learning :

  - MSA-11-0020
    Continue links in error messages can lead offsite

  - MSA-11-0024

    reCAPTCHA images were being authenticated from an older
    server

  - MSA-11-0025

    Group names in user upload CSV not escaped

  - MSA-11-0026

    Fields in user upload CSV not escaped

  - MSA-11-0031

    Forms API constant issue

  - MSA-11-0032

    MNET SSL validation issue

  - MSA-11-0036

    Messaging refresh vulnerability

  - MSA-11-0037

    Course section editing injection vulnerability

  - MSA-11-0038

    Database injection protection strengthened"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=182737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=188313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=188314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=188318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=188319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=188320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/moodle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2338"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moodle packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.9.9.dfsg2-2.1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"moodle", reference:"1.9.9.dfsg2-2.1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
