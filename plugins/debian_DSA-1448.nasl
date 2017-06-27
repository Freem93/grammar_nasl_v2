#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1448. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29857);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2007-2807");
  script_bugtraq_id(24070);
  script_osvdb_id(36237);
  script_xref(name:"DSA", value:"1448");

  script_name(english:"Debian DSA-1448-1 : eggdrop - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that eggdrop, an advanced IRC robot, was vulnerable
to a buffer overflow which could result in a remote user executing
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=427157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1448"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the eggdrop package.

For the old stable distribution (sarge), this problem has been fixed
in version 1.6.17-3sarge1.

For the stable distribution (etch), this problem has been fixed in
version 1.6.18-1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eggdrop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"eggdrop", reference:"1.6.17-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"eggdrop-data", reference:"1.6.17-3sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"eggdrop", reference:"1.6.18-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"eggdrop-data", reference:"1.6.18-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
