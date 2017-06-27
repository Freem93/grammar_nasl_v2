#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3426. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87509);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_osvdb_id(128557, 128845, 130089, 130525, 130832, 131685);
  script_xref(name:"DSA", value:"3426");

  script_name(english:"Debian DSA-3426-2 : ctdb - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update for linux issued as DSA-3426-1 and DSA-3434-1 to address
CVE-2015-8543 uncovered a bug in ctdb, a clustered database to store
temporary data, leading to broken clusters. Updated packages are now
available to address this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=813406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ctdb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ctdb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3426"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ctdb packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.12+git20120201-5.

For the stable distribution (jessie), this problem has been fixed in
version 2.5.4+debian0-4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ctdb", reference:"1.12+git20120201-5")) flag++;
if (deb_check(release:"7.0", prefix:"ctdb-dbg", reference:"1.12+git20120201-5")) flag++;
if (deb_check(release:"7.0", prefix:"libctdb-dev", reference:"1.12+git20120201-5")) flag++;
if (deb_check(release:"8.0", prefix:"ctdb", reference:"2.5.4+debian0-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ctdb-dbg", reference:"2.5.4+debian0-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ctdb-pcp-pmda", reference:"2.5.4+debian0-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libctdb-dev", reference:"2.5.4+debian0-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
