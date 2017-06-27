#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-191. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15028);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2002-1131", "CVE-2002-1132", "CVE-2002-1276");
  script_bugtraq_id(5763, 5949);
  script_osvdb_id(4262, 4263, 4264, 4265, 9227);
  script_xref(name:"DSA", value:"191");

  script_name(english:"Debian DSA-191-1 : squirrelmail - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several cross site scripting vulnerabilities have been found in
squirrelmail, a feature-rich webmail package written in PHP4. The
Common Vulnerabilities and Exposures (CVE) project identified the
following vulnerabilities :

  - CAN-2002-1131: User input is not always sanitized so
    execution of arbitrary code on a client computer is
    possible. This can happen after following a malicious
    URL or by viewing a malicious addressbook entry.
  - CAN-2002-1132: Another problem could make it possible
    for an attacker to gain sensitive information under some
    conditions. When a malformed argument is appended to a
    link, an error page will be generated which contains the
    absolute pathname of the script. However, this
    information is available through the Contents file of
    the distribution anyway.

These problems have been fixed in version 1.2.6-1.1 for the current
stable distribution (woody) and in version 1.2.8-1.1 for the unstable
distribution (sid). The old stable distribution (potato) is not
affected since it doesn't contain a squirrelmail package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-191"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the squirrelmail package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"squirrelmail", reference:"1.2.6-1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
