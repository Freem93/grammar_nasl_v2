#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2276. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55554);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-2529", "CVE-2011-2535");
  script_bugtraq_id(48431);
  script_osvdb_id(73307, 73308, 73309);
  script_xref(name:"DSA", value:"2276");

  script_name(english:"Debian DSA-2276-1 : asterisk - multiple denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Belanger reported a vulnerability in Asterisk identified as
AST-2011-008(CVE-2011-2529 ) through which an unauthenticated attacker
may crash an Asterisk server remotely. A package containing a NULL
char causes the SIP header parser to alter unrelated memory
structures.

Jared Mauch reported a vulnerability in Asterisk identified as
AST-2011-009through which an unauthenticated attacker may crash an
Asterisk server remotely. If a user sends a package with a Contact
header with a missing left angle bracket (<) the server will crash. A
possible workaround is to disable chan_sip.

The vulnerability identified as AST-2011-010(CVE-2011-2535 ) reported
about an input validation error in the IAX2 channel driver. An
unauthenticated attacker may crash an Asterisk server remotely by
sending a crafted option control frame."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=631445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=631446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=631448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2276"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.21.2~dfsg-3+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.2.9-2+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/12");
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
if (deb_check(release:"5.0", prefix:"asterisk", reference:"1.4.21.2~dfsg-3+lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk", reference:"1.6.2.9-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-config", reference:"1.6.2.9-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dbg", reference:"1.6.2.9-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dev", reference:"1.6.2.9-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-doc", reference:"1.6.2.9-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-h323", reference:"1.6.2.9-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-sounds-main", reference:"1.6.2.9-2+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
