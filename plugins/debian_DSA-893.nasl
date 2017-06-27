#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-893. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22759);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2005-3325", "CVE-2005-4878");
  script_bugtraq_id(15199);
  script_osvdb_id(20836, 20837, 24306);
  script_xref(name:"DSA", value:"893");

  script_name(english:"Debian DSA-893-1 : acidlab - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Remco Verhoef has discovered a vulnerability in acidlab, Analysis
Console for Intrusion Databases, and in acidbase, Basic Analysis and
Security Engine, which can be exploited by malicious users to conduct
SQL injection attacks.

The maintainers of Analysis Console for Intrusion Databases (ACID) in
Debian, of which BASE is a fork off, after a security audit of both
BASE and ACID have determined that the flaw found not only affected
the base_qry_main.php (in BASE) or acid_qry_main.php (in ACID)
component but was also found in other elements of the consoles due to
improper parameter validation and filtering.

All the SQL injection bugs and Cross Site Scripting bugs found have
been fixed in the Debian package, closing all the different attack
vectors detected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=335998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=336788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-893"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the acidlab and acidbase package.

For the old stable distribution (woody) this problem has been fixed in
version 0.9.6b20-2.1.

For the stable distribution (sarge) this problem has been fixed in
version 0.9.6b20-10.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:acidlab");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"acidlab", reference:"0.9.6b20-2.1")) flag++;
if (deb_check(release:"3.1", prefix:"acidlab", reference:"0.9.6b20-10.1")) flag++;
if (deb_check(release:"3.1", prefix:"acidlab-doc", reference:"0.9.6b20-10.1")) flag++;
if (deb_check(release:"3.1", prefix:"acidlab-mysql", reference:"0.9.6b20-10.1")) flag++;
if (deb_check(release:"3.1", prefix:"acidlab-pgsql", reference:"0.9.6b20-10.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
