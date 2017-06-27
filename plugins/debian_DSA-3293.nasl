#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3293. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84300);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/07/14 13:43:56 $");

  script_osvdb_id(120268);
  script_xref(name:"DSA", value:"3293");

  script_name(english:"Debian DSA-3293-1 : pyjwt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tim McLean discovered that pyjwt, a Python implementation of JSON Web
Token, would try to verify an HMAC signature using an RSA or ECDSA
public key as secret. This could allow remote attackers to trick
applications expecting tokens signed with asymmetric keys, into
accepting arbitrary tokens. For more information see:
https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web
-token-libraries/."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=781640"
  );
  # https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?085aa340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pyjwt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3293"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pyjwt packages.

For the stable distribution (jessie), this problem has been fixed in
version 0.2.1-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pyjwt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"python-jwt", reference:"0.2.1-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python3-jwt", reference:"0.2.1-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
