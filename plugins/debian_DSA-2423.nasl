#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2423. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58198);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:57 $");

  script_cve_id("CVE-2011-5084", "CVE-2011-5085", "CVE-2012-0317", "CVE-2012-0318", "CVE-2012-0319", "CVE-2012-0320", "CVE-2012-1262", "CVE-2012-1497");
  script_bugtraq_id(52138);
  script_osvdb_id(79470, 79471, 79472, 79473, 79474);
  script_xref(name:"DSA", value:"2423");

  script_name(english:"Debian DSA-2423-1 : movabletype-opensource - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Movable Type, a blogging
system :

Under certain circumstances, a user who has 'Create Entries' or'Manage
Blog' permissions may be able to read known files on the local file
system.

The file management system contains shell command injection
vulnerabilities, the most serious of which may lead to arbitrary OS
command execution by a user who has a permission to sign-in to the
admin script and also has a permission to upload files.

Session hijack and cross-site request forgery vulnerabilities exist in
the commenting and the community script. A remote attacker could
hijack the user session or could execute arbitrary script code on
victim's browser under the certain circumstances.

Templates which do not escape variable properly and mt-wizard.cgi
contain cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=631437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=661064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/movabletype-opensource"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2423"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the movabletype-opensource packages.

For the stable distribution (squeeze), these problems have been fixed
in version 4.3.8+dfsg-0+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:movabletype-opensource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"movabletype-opensource", reference:"4.3.8+dfsg-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"movabletype-plugin-core", reference:"4.3.8+dfsg-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"movabletype-plugin-zemanta", reference:"4.3.8+dfsg-0+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
