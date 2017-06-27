#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3149. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81129);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/16 15:48:49 $");

  script_cve_id("CVE-2014-8126");
  script_bugtraq_id(72019);
  script_xref(name:"DSA", value:"3149");

  script_name(english:"Debian DSA-3149-1 : condor - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Weimer, of Red Hat Product Security, discovered an issue in
condor, a distributed workload management system. Upon job completion,
it can optionally notify a user by sending an email; the mailx
invocation used in that process allowed for any authenticated user
able to submit jobs, to execute arbitrary code with the privileges of
the condor user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=775276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/condor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the condor packages.

For the stable distribution (wheezy), this problem has been fixed in
version 7.8.2~dfsg.1-1+deb7u3.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version
8.2.3~dfsg.1-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:condor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"condor", reference:"7.8.2~dfsg.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"condor-dbg", reference:"7.8.2~dfsg.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"condor-dev", reference:"7.8.2~dfsg.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"condor-doc", reference:"7.8.2~dfsg.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libclassad-dev", reference:"7.8.2~dfsg.1-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libclassad3", reference:"7.8.2~dfsg.1-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
