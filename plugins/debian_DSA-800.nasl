#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-800. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19570);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2005-2491");
  script_bugtraq_id(14620);
  script_osvdb_id(18906);
  script_xref(name:"DSA", value:"800");

  script_name(english:"Debian DSA-800-1 : pcre3 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow with subsequent buffer overflow has been detected
in PCRE, the Perl Compatible Regular Expressions library, which allows
an attacker to execute arbitrary code.

Since several packages link dynamically to this library you are
advised to restart the corresponding services or programs
respectively. The command 'apt-cache showpkg libpcre3' will list the
corresponding packages in the 'Reverse Depends:' section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=324531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-800"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpcre3 package.

For the old stable distribution (woody) this problem has been fixed in
version 3.4-1.1woody1.

For the stable distribution (sarge) this problem has been fixed in
version 4.5-1.2sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pcre3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libpcre3", reference:"3.4-1.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libpcre3-dev", reference:"3.4-1.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"pgrep", reference:"3.4-1.1woody1")) flag++;
if (deb_check(release:"3.1", prefix:"libpcre3", reference:"4.5-1.2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libpcre3-dev", reference:"4.5-1.2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcregrep", reference:"4.5-1.2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pgrep", reference:"4.5-1.2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
