#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1241. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23946);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/08/13 14:23:42 $");

  script_cve_id("CVE-2006-6142");
  script_osvdb_id(31720, 31721, 31722);
  script_xref(name:"DSA", value:"1241");

  script_name(english:"Debian DSA-1241-1 : squirrelmail - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Martijn Brinkers discovered cross-site scripting vulnerabilities in
the mailto parameter of webmail.php, the session and delete_draft
parameters of compose.php and through a shortcoming in the magicHTML
filter. An attacker could abuse these to execute malicious JavaScript
in the user's webmail session. 

Also, a workaround was made for Internet Explorer <= 5: IE will
attempt to guess the MIME type of attachments based on content, not
the MIME header sent. Attachments could fake to be a 'harmless' JPEG,
while they were in fact HTML that Internet Explorer would render."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1241"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squirrelmail package.

For the stable distribution (sarge) these problems have been fixed in
version 2:1.4.4-10.

For the upcoming stable distribution (etch) these problems have been
fixed in version 2:1.4.9a-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"squirrelmail", reference:"2:1.4.4-10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
