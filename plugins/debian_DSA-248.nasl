#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-248. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15085);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2003-0057");
  script_bugtraq_id(6689, 6690);
  script_xref(name:"DSA", value:"248");

  script_name(english:"Debian DSA-248-1 : hypermail - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar discovered two problems in hypermail, a program to
create HTML archives of mailing lists.

An attacker could craft a long filename for an attachment that would
overflow two buffers when a certain option for interactive use was
given, opening the possibility to inject arbitrary code. This code
would then be executed under the user id hypermail runs as, mostly as
a local user. Automatic and silent use of hypermail does not seem to
be affected.

The CGI program mail, which is not installed by the Debian package,
does a reverse look-up of the user's IP number and copies the
resulting hostname into a fixed-size buffer. A specially crafted DNS
reply could overflow this buffer, opening the program to an exploit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-248"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the hypermail packages.

For the stable distribution (woody) this problem has been fixed in
version 2.1.3-2.0.

For the old stable distribution (potato) this problem has been fixed
in version 2.0b25-1.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypermail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"hypermail", reference:"2.0b25-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"hypermail", reference:"2.1.3-2.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
