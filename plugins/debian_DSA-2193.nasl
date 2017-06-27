#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2193. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52691);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1006", "CVE-2011-1022");
  script_bugtraq_id(46578, 46729);
  script_osvdb_id(72519);
  script_xref(name:"DSA", value:"2193");

  script_name(english:"Debian DSA-2193-1 : libcgroup - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in libcgroup, a library to control
and monitor control groups :

  - CVE-2011-1006
    Heap-based buffer overflow by converting list of
    controllers for given task into an array of strings
    could lead to privilege escalation by a local attacker.

  - CVE-2011-1022
    libcgroup did not properly check the origin of Netlink
    messages, allowing a local attacker to send crafted
    Netlink messages which could lead to privilege
    escalation.

The oldstable distribution (lenny) does not contain libcgroup
packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=615987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libcgroup"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2193"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libcgroup packages.

For the stable distribution (squeeze), this problem has been fixed in
version 0.36.2-3+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcgroup");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/17");
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
if (deb_check(release:"6.0", prefix:"cgroup-bin", reference:"0.36.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libcgroup-dev", reference:"0.36.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libcgroup1", reference:"0.36.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpam-cgroup", reference:"0.36.2-3+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
