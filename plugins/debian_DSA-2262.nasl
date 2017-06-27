#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2262. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55146);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_osvdb_id(73285, 73286, 73287, 75056, 75057, 75058, 75059, 75060, 75061, 75062, 75063);
  script_xref(name:"DSA", value:"2262");

  script_name(english:"Debian DSA-2262-1 : moodle - several vulnerabilities");
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

  - MSA-11-0002
    Cross-site request forgery vulnerability in RSS block

  - MSA-11-0003

    Cross-site scripting vulnerability in tag autocomplete

  - MSA-11-0008

    IMS enterprise enrolment file may disclose sensitive
    information

  - MSA-11-0011

    Multiple cross-site scripting problems in media filter

  - MSA-11-0015

    Cross Site Scripting through URL encoding

  - MSA-11-0013

    Group/Quiz permissions issue"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=170002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=170003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=170009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=170012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=175592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moodle.org/mod/forum/discuss.php?d=175590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/moodle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2262"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moodle packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.9.9.dfsg2-2.1+squeeze1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/16");
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
if (deb_check(release:"6.0", prefix:"moodle", reference:"1.9.9.dfsg2-2.1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
