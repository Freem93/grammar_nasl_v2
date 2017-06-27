#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-988. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22854);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:30:25 $");

  script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");
  script_osvdb_id(23384, 23385, 23386);
  script_xref(name:"DSA", value:"988");

  script_name(english:"Debian DSA-988-1 : squirrelmail - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2006-0188
    Martijn Brinkers and Ben Maurer found a flaw in
    webmail.php that allows remote attackers to inject
    arbitrary web pages into the right frame via a URL in
    the right_frame parameter.

  - CVE-2006-0195
    Martijn Brinkers and Scott Hughes discovered an
    interpretation conflict in the MagicHTML filter that
    allows remote attackers to conduct cross-site scripting
    (XSS) attacks via style sheet specifiers with invalid
    (1) '/*' and '*/' comments, or (2) slashes inside the
    'url' keyword, which is processed by some web browsers
    including Internet Explorer.

  - CVE-2006-0377
    Vicente Aguilera of Internet Security Auditors, S.L.
    discovered a CRLF injection vulnerability, which allows
    remote attackers to inject arbitrary IMAP commands via
    newline characters in the mailbox parameter of the
    sqimap_mailbox_select command, aka 'IMAP injection.'
    There's no known way to exploit this yet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=354062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=354063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=354064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=355424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-988"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squirrelmail package.

For the old stable distribution (woody) these problems have been fixed
in version 1.2.6-5.

For the stable distribution (sarge) these problems have been fixed in
version 2:1.4.4-8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/01");
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
if (deb_check(release:"3.0", prefix:"squirrelmail", reference:"1.2.6-5")) flag++;
if (deb_check(release:"3.1", prefix:"squirrelmail", reference:"2:1.4.4-8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
