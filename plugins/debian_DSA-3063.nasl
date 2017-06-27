#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3063. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78834);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-8483");
  script_bugtraq_id(70740);
  script_xref(name:"DSA", value:"3063");

  script_name(english:"Debian DSA-3063-1 : quassel - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds read vulnerability was discovered in Quassel-core,
one of the components of the distributed IRC client Quassel. An
attacker can send a crafted message that crash to component causing a
denial of services or disclosure of information from process memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=766962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/quassel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3063"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quassel packages.

For the stable distribution (wheezy), this problem has been fixed in
version 0.8.0-1+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quassel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"quassel", reference:"0.8.0-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quassel-client", reference:"0.8.0-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quassel-client-kde4", reference:"0.8.0-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quassel-core", reference:"0.8.0-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quassel-data", reference:"0.8.0-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quassel-data-kde4", reference:"0.8.0-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"quassel-kde4", reference:"0.8.0-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
