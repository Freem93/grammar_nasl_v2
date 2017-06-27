#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1782. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38641);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-4866", "CVE-2008-5616", "CVE-2009-0385");
  script_bugtraq_id(33502);
  script_osvdb_id(50261, 50838, 51643);
  script_xref(name:"DSA", value:"1782");

  script_name(english:"Debian DSA-1782-1 : mplayer - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in mplayer, a movie
player for Unix-like systems. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-0385
    It was discovered that watching a malformed 4X movie
    file could lead to the execution of arbitrary code.

  - CVE-2008-4866
    It was discovered that multiple buffer overflows could
    lead to the execution of arbitrary code.

  - CVE-2008-5616
    It was discovered that watching a malformed TwinVQ file
    could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1782"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mplayer packages.

For the oldstable distribution (etch), these problems have been fixed
in version 1.0~rc1-12etch7.

For the stable distribution (lenny), mplayer links against
ffmpeg-debian."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"mplayer", reference:"1.0~rc1-12etch7")) flag++;
if (deb_check(release:"4.0", prefix:"mplayer-doc", reference:"1.0~rc1-12etch7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
