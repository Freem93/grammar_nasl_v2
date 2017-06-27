#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3440. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87852);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-5602");
  script_osvdb_id(125548);
  script_xref(name:"DSA", value:"3440");

  script_name(english:"Debian DSA-3440-1 : sudo - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When sudo is configured to allow a user to edit files under a
directory that they can already write to without using sudo, they can
actually edit (read and write) arbitrary files. Daniel Svartman
reported that a configuration like this might be introduced
unintentionally if the editable files are specified using wildcards,
for example :

operator ALL=(root) sudoedit /home/*/*/test.txt

The default behaviour of sudo has been changed so that it does not
allow editing of a file in a directory that the user can write to, or
that is reached by following a symlink in a directory that the user
can write to. These restrictions can be disabled, but this is strongly
discouraged."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=804149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/sudo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/sudo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3440"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sudo packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.8.5p2-1+nmu3+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1.8.10p3-1+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"sudo", reference:"1.8.5p2-1+nmu3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"sudo-ldap", reference:"1.8.5p2-1+nmu3+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"sudo", reference:"1.8.10p3-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"sudo-ldap", reference:"1.8.10p3-1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
