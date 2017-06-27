#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-662. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16283);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0104", "CVE-2005-0152");
  script_osvdb_id(13145, 13386);
  script_xref(name:"DSA", value:"662");

  script_name(english:"Debian DSA-662-2 : squirrelmail - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrew Archibald discovered that the last update to squirrelmail which
was intended to fix several problems caused a regression which got
exposed when the user hits a session timeout.  For completeness below
is the original advisory text :

  Several vulnerabilities have been discovered in Squirrelmail, a
  commonly used webmail system. The Common Vulnerabilities and
  Exposures project identifies the following problems :

    - CAN-2005-0104
      Upstream developers noticed that an unsanitised
      variable could lead to cross site scripting.

    - CAN-2005-0152

      Grant Hollingworth discovered that under certain
      circumstances URL manipulation could lead to the
      execution of arbitrary code with the privileges of
      www-data. This problem only exists in version 1.2.6 of
      Squirrelmail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=292714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=295836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-662"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squirrelmail package.

For the stable distribution (woody) these problems have been fixed in
version 1.2.6-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/20");
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
if (deb_check(release:"3.0", prefix:"squirrelmail", reference:"1.2.6-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
