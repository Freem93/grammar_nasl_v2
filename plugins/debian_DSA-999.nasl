#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-999. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22865);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:30:25 $");

  script_cve_id("CVE-2006-1062", "CVE-2006-1063", "CVE-2006-1064");
  script_osvdb_id(23694, 23695, 23696);
  script_xref(name:"DSA", value:"999");

  script_name(english:"Debian DSA-999-1 : lurker - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in lurker, an
archive tool for mailing lists with integrated search engine. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2006-1062
    Lurker's mechanism for specifying configuration files
    was vulnerable to being overridden. As lurker includes
    sections of unparsed config files in its output, an
    attacker could manipulate lurker into reading any file
    readable by the www-data user.

  - CVE-2006-1063
    It is possible for a remote attacker to create or
    overwrite files in any writable directory that is named
    'mbox'.

  - CVE-2006-1064
    Missing input sanitising allows an attacker to inject
    arbitrary web script or HTML."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-999"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lurker package.

The old stable distribution (woody) does not contain lurker packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.2-5sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lurker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"lurker", reference:"1.2-5sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
