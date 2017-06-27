#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-535. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15372);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521", "CVE-2004-0639");
  script_bugtraq_id(10246, 10439);
  script_osvdb_id(6514, 6841, 8291, 8292);
  script_xref(name:"DSA", value:"535");

  script_name(english:"Debian DSA-535-1 : squirrelmail - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Four vulnerabilities were discovered in squirrelmail :

  - CAN-2004-0519
    Multiple cross-site scripting (XSS) vulnerabilities in
    SquirrelMail 1.4.2 allow remote attackers to execute
    arbitrary script as other users and possibly steal
    authentication information via multiple attack vectors,
    including the mailbox parameter in compose.php.

  - CAN-2004-0520

    Cross-site scripting (XSS) vulnerability in mime.php for
    SquirrelMail before 1.4.3 allows remote attackers to
    insert arbitrary HTML and script via the content-type
    mail header, as demonstrated using read_body.php.

  - CAN-2004-0521

    SQL injection vulnerability in SquirrelMail before 1.4.3
    RC1 allows remote attackers to execute unauthorized SQL
    statements, with unknown impact, probably via
    abook_database.php.

  - CAN-2004-0639

    Multiple cross-site scripting (XSS) vulnerabilities in
    Squirrelmail 1.2.10 and earlier allow remote attackers
    to inject arbitrary HTML or script via (1) the $mailer
    variable in read_body.php, (2) the $senderNames_part
    variable in mailbox_display.php, and possibly other
    vectors including (3) the $event_title variable or (4)
    the $event_text variable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-535"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody), these problems have been
fixed in version 1:1.2.6-1.4.

We recommend that you update your squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"squirrelmail", reference:"1.2.6-1.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
