#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1029. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22571);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/06 20:12:49 $");

  script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
  script_bugtraq_id(16187, 16364, 16720);
  script_osvdb_id(22290, 22291, 22705, 23362, 23363, 23364);
  script_xref(name:"DSA", value:"1029");

  script_name(english:"Debian DSA-1029-1 : libphp-adodb - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in libphp-adodb, the
'adodb' database abstraction layer for PHP. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2006-0146
    Andreas Sandblad discovered that improper user input
    sanitisation results in a potential remote SQL injection
    vulnerability enabling an attacker to compromise
    applications, access or modify data, or exploit
    vulnerabilities in the underlying database
    implementation. This requires the MySQL root password to
    be empty. It is fixed by limiting access to the script
    in question.

  - CVE-2006-0147
    A dynamic code evaluation vulnerability allows remote
    attackers to execute arbitrary PHP functions via the
    'do' parameter.

  - CVE-2006-0410
    Andy Staudacher discovered a SQL injection vulnerability
    due to insufficient input sanitising that allows remote
    attackers to execute arbitrary SQL commands.

  - CVE-2006-0806
    GulfTech Security Research discovered multiple
    cross-site scripting vulnerabilities due to improper
    user-supplied input sanitisation. Attackers can exploit
    these vulnerabilities to cause arbitrary scripts to be
    executed in the browser of an unsuspecting user's
    machine, or result in the theft of cookie-based
    authentication credentials."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=349985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=358872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1029"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libphp-adodb package.

For the old stable distribution (woody) these problems have been fixed
in version 1.51-1.2.

For the stable distribution (sarge) these problems have been fixed in
version 4.52-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp-adodb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libphp-adodb", reference:"1.51-1.2")) flag++;
if (deb_check(release:"3.1", prefix:"libphp-adodb", reference:"4.52-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
