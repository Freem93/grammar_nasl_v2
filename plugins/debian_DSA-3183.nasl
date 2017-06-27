#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3183. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81793);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/11 23:27:58 $");

  script_cve_id("CVE-2013-2184", "CVE-2014-9057", "CVE-2015-1592");
  script_xref(name:"DSA", value:"3183");

  script_name(english:"Debian DSA-3183-1 : movabletype-opensource - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Movable Type, a
blogging system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2013-2184
    Unsafe use of Storable::thaw in the handling of comments
    to blog posts could allow remote attackers to include
    and execute arbitrary local Perl files or possibly
    remotely execute arbitrary code.

  - CVE-2014-9057
    Netanel Rubin from Check Point Software Technologies
    discovered a SQL injection vulnerability in the XML-RPC
    interface allowing remote attackers to execute arbitrary
    SQL commands.

  - CVE-2015-1592
    The Perl Storable::thaw function is not properly used,
    allowing remote attackers to include and execute
    arbitrary local Perl files and possibly remotely execute
    arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=712602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=774192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/movabletype-opensource"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3183"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the movabletype-opensource packages.

For the stable distribution (wheezy), these problems have been fixed
in version 5.1.4+dfsg-4+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SixApart MovableType Storable Perl Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:movabletype-opensource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
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
if (deb_check(release:"7.0", prefix:"movabletype-opensource", reference:"5.1.4+dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"movabletype-plugin-core", reference:"5.1.4+dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"movabletype-plugin-zemanta", reference:"5.1.4+dfsg-4+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
