#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2566. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62721);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-5671");
  script_osvdb_id(86616);
  script_xref(name:"DSA", value:"2566");

  script_name(english:"Debian DSA-2566-1 : exim4 - heap-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Exim, a mail transport agent, is not properly
handling the decoding of DNS records for DKIM. Specifically, crafted
records can yield to a heap-based buffer overflow. An attacker can
exploit this flaw to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2566"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exim4 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.72-6+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"exim4", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-base", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-config", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-heavy", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-light", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-light-dbg", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-dbg", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-dev", reference:"4.72-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"eximon4", reference:"4.72-6+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
