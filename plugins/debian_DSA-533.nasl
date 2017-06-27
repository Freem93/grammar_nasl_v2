#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-533. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15370);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/08/13 14:23:42 $");

  script_cve_id("CVE-2004-0591");
  script_bugtraq_id(10588);
  script_xref(name:"DSA", value:"533");

  script_name(english:"Debian DSA-533-1 : courier - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cross-site scripting vulnerability was discovered in sqwebmail, a
web mail application provided by the courier mail suite, whereby an
attacker could cause web script to be executed within the security
context of the sqwebmail application by injecting it via an email
message."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody), this problem has been
fixed in version 0.37.3-2.5.

We recommend that you update your courier package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"courier-authdaemon", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-authmysql", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-base", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-debug", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-doc", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-imap", reference:"1.4.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-ldap", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-maildrop", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mlm", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mta", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pcp", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pop", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"courier-webadmin", reference:"0.37.3-2.5")) flag++;
if (deb_check(release:"3.0", prefix:"sqwebmail", reference:"0.37.3-2.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
