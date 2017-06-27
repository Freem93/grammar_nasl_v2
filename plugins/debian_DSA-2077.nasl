#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2077. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48220);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-0211", "CVE-2010-0212");
  script_bugtraq_id(41770);
  script_xref(name:"DSA", value:"2077");

  script_name(english:"Debian DSA-2077-1 : openldap - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two remote vulnerabilities have been discovered in OpenLDAP. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2010-0211
    The slap_modrdn2mods function in modrdn.c in OpenLDAP
    2.4.22 does not check the return value of a call to the
    smr_normalize function, which allows remote attackers to
    cause a denial of service (segmentation fault) and
    possibly execute arbitrary code via a modrdn call with
    an RDN string containing invalid UTF-8 sequences.

  - CVE-2010-0212
    OpenLDAP 2.4.22 allows remote attackers to cause a
    denial of service (crash) via a modrdn call with a
    zero-length RDN destination string."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2077"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openldap packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.4.11-1+lenny2. (The missing update for the mips architecture
will be provided soon.)"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"ldap-utils", reference:"2.4.11-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libldap-2.4-2", reference:"2.4.11-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libldap-2.4-2-dbg", reference:"2.4.11-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libldap2-dev", reference:"2.4.11-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"slapd", reference:"2.4.11-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"slapd-dbg", reference:"2.4.11-1+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
