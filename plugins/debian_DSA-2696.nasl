#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2696. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66677);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-3551");
  script_bugtraq_id(60117);
  script_xref(name:"DSA", value:"2696");

  script_name(english:"Debian DSA-2696-1 : otrs2 - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in the Open Ticket Request System,
which can be exploited by malicious users to disclose potentially
sensitive information.

An attacker with a valid agent login could manipulate URLs in the
ticket split mechanism to see contents of tickets they are not
permitted to see.

The oldstable distribution (squeeze) is not affected by this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/otrs2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2696"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the otrs2 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 3.1.7+dfsg1-8+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"otrs", reference:"3.1.7+dfsg1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"otrs2", reference:"3.1.7+dfsg1-8+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
