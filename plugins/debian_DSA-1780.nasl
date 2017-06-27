#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1780. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38202);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0663", "CVE-2009-1341");
  script_osvdb_id(54171, 54176);
  script_xref(name:"DSA", value:"1780");

  script_name(english:"Debian DSA-1780-1 : libdbd-pg-perl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in libdbd-pg-perl, the DBI
driver module for PostgreSQL database access (DBD::Pg).

  - CVE-2009-0663
    A heap-based buffer overflow may allow attackers to
    execute arbitrary code through applications which read
    rows from the database using the pg_getline and getline
    functions. (More common retrieval methods, such as
    selectall_arrayref and fetchrow_array, are not
    affected.)

  - CVE-2009-1341
    A memory leak in the routine which unquotes BYTEA values
    returned from the database allows attackers to cause a
    denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1780"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libdbd-pg-perl package.

For the old stable distribution (etch), these problems have been fixed
in version 1.49-2+etch1.

For the stable distribution (lenny) and the unstable distribution
(sid), these problems have been fixed in version 2.1.3-1 before the
release of lenny."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdbd-pg-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libdbd-pg-perl", reference:"1.49-2+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libdbd-pg-perl", reference:"2.1.3-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
