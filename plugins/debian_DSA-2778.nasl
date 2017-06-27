#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2778. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70403);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-4365");
  script_bugtraq_id(62939);
  script_osvdb_id(98300);
  script_xref(name:"DSA", value:"2778");

  script_name(english:"Debian DSA-2778-1 : libapache2-mod-fcgid - heap-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Robert Matthews discovered that the Apache FCGID module, a FastCGI
implementation for Apache HTTP Server, fails to perform adequate
boundary checks on user-supplied input. This may allow a remote
attacker to cause a heap-based buffer overflow, resulting in a denial
of service or potentially allowing the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libapache2-mod-fcgid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libapache2-mod-fcgid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2778"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libapache2-mod-fcgid packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1:2.3.6-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 1:2.3.6-1.2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-fcgid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libapache2-mod-fcgid", reference:"1:2.3.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-fcgid-dbg", reference:"1:2.3.6-1+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-fcgid", reference:"1:2.3.6-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-fcgid-dbg", reference:"1:2.3.6-1.2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
