#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1659. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34492);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/03 11:20:09 $");

  script_cve_id("CVE-2008-2469");
  script_xref(name:"DSA", value:"1659");

  script_name(english:"Debian DSA-1659-1 : libspf2 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky discovered that libspf2, an implementation of the Sender
Policy Framework (SPF) used by mail servers for mail filtering,
handles malformed TXT records incorrectly, leading to a buffer
overflow condition (CVE-2008-2469 ).

Note that the SPF configuration template in Debian's Exim
configuration recommends to use libmail-spf-query-perl, which does not
suffer from this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1659"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libspf2 package.

For the stable distribution (etch), this problem has been fixed in
version 1.2.5-4+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspf2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libspf2-2", reference:"1.2.5-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libspf2-dev", reference:"1.2.5-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"spfquery", reference:"1.2.5-4+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
