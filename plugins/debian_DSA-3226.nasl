#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3226. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82839);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2012-6696", "CVE-2012-6697", "CVE-2015-6674");
  script_bugtraq_id(52561);
  script_osvdb_id(80263, 120290, 126780);
  script_xref(name:"DSA", value:"3226");

  script_name(english:"Debian DSA-3226-1 : inspircd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adam discovered several problems in inspircd, an IRC daemon :

  - An incomplete patch for CVE-2012-1836 failed to
    adequately resolve the problem where maliciously crafted
    DNS requests could lead to remote code execution through
    a heap-based buffer overflow.
  - The incorrect processing of specific DNS packets could
    trigger an infinite loop, thus resulting in a denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=780880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/inspircd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3226"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the inspircd packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.0.5-1+deb7u1.


For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 2.0.16-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inspircd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"inspircd", reference:"2.0.5-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"inspircd-dbg", reference:"2.0.5-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
