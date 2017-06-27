#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-634. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16131);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1182");
  script_osvdb_id(12859);
  script_xref(name:"DSA", value:"634");

  script_name(english:"Debian DSA-634-1 : hylafax - weak hostname and username validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Patrice Fournier discovered a vulnerability in the authorisation
subsystem of hylafax, a flexible client/server fax system. A local or
remote user guessing the contents of the hosts.hfaxd database could
gain unauthorised access to the fax system.

Some installations of hylafax may actually utilise the weak hostname
and username validation for authorized uses. For example, hosts.hfaxd
entries that may be common are

  192.168.0 username:uid:pass:adminpass user@host

After updating, these entries will need to be modified in order to
continue to function. Respectively, the correct entries should be

  192.168.0.[0-9]+ username@:uid:pass:adminpass user@host

Unless such matching of 'username' with 'otherusername' and 'host'
with 'hostname' is desired, the proper form of these entries should
include the delimiter and markers like this

  @192.168.0.[0-9]+$ ^username@:uid:pass:adminpass ^user@host$"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-634"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the hylafax packages.

For the stable distribution (woody) this problem has been fixed in
version 4.1.1-3.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hylafax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"hylafax-client", reference:"4.1.1-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-doc", reference:"4.1.1-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-server", reference:"4.1.1-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
