#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2038. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45560);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2010-0420", "CVE-2010-0423");
  script_bugtraq_id(38294);
  script_osvdb_id(62439, 62440);
  script_xref(name:"DSA", value:"2038");

  script_name(english:"Debian DSA-2038-1 : pidgin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Pidgin, a multi
protocol instant messaging client. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2010-0420
    Crafted nicknames in the XMPP protocol can crash Pidgin
    remotely.

  - CVE-2010-0423
    Remote contacts may send too many custom smilies,
    crashing Pidgin.

Since a few months, Microsoft's servers for MSN have changed the
protocol, making Pidgin non-functional for use with MSN. It is not
feasible to port these changes to the version of Pidgin in Debian
Lenny. This update formalises that situation by disabling the protocol
in the client. Users of the MSN protocol are advised to use the
version of Pidgin in the repositories of www.backports.org."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=566775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2038"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pidgin package.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.3-4lenny6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"finch", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"finch-dev", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libpurple-bin", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libpurple-dev", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libpurple0", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin-data", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin-dbg", reference:"2.4.3-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin-dev", reference:"2.4.3-4lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
