#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1952. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44817);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/03/30 13:45:23 $");

  script_cve_id("CVE-2007-2383", "CVE-2008-3903", "CVE-2008-7220", "CVE-2009-0041", "CVE-2009-3727", "CVE-2009-4055");
  script_bugtraq_id(36926, 37153);
  script_osvdb_id(43328, 46312, 48473, 51373, 59697, 60569);
  script_xref(name:"DSA", value:"1952");

  script_name(english:"Debian DSA-1952-1 : asterisk - several vulnerabilities, end-of-life announcement in oldstable");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in asterisk, an Open
Source PBX and telephony toolkit. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2009-0041
    It is possible to determine valid login names via
    probing, due to the IAX2 response from asterisk
    (AST-2009-001).

  - CVE-2008-3903
    It is possible to determine a valid SIP username, when
    Digest authentication and authalwaysreject are enabled
    (AST-2009-003).

  - CVE-2009-3727
    It is possible to determine a valid SIP username via
    multiple crafted REGISTER messages (AST-2009-008).

  - CVE-2008-7220 CVE-2007-2383
    It was discovered that asterisk contains an obsolete
    copy of the Prototype JavaScript framework, which is
    vulnerable to several security issues. This copy is
    unused and now removed from asterisk (AST-2009-009).

  - CVE-2009-4055
    It was discovered that it is possible to perform a
    denial of service attack via RTP comfort noise payload
    with a long data length (AST-2009-010).

The current version in oldstable is not supported by upstream anymore
and is affected by several security issues. Backporting fixes for
these and any future issues has become unfeasible and therefore we
need to drop our security support for the version in oldstable. We
recommend that all asterisk users upgrade to the stable distribution
(lenny)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=513413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=522528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=554487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=554486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=559103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-7220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1952"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the stable distribution (lenny), these problems have been fixed in
version 1:1.4.21.2~dfsg-3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"asterisk", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"asterisk-config", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"asterisk-dbg", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"asterisk-dev", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"asterisk-doc", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"asterisk-h323", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"asterisk-sounds-main", reference:"1:1.4.21.2~dfsg-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
