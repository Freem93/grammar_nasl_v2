#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3803. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97589);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/17 14:19:06 $");

  script_cve_id("CVE-2016-10243");
  script_osvdb_id(148861, 152094, 152453, 152521, 152685, 152705, 152709, 152728, 152729, 152962, 153186);
  script_xref(name:"DSA", value:"3803");

  script_name(english:"Debian DSA-3803-1 : texlive-base - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that texlive-base, the TeX Live package which
provides the essential TeX programs and files, whitelists mpost as an
external program to be run from within the TeX source code (called
\write18). Since mpost allows to specify other programs to be run, an
attacker can take advantage of this flaw for arbitrary code execution
when compiling a TeX document."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/texlive-base"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3803"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the texlive-base packages.

For the stable distribution (jessie), this problem has been fixed in
version 2014.20141024-2+deb8u1.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 2016.20161130-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"latex-beamer", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"latex-xcolor", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pgf", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-base", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-fonts-recommended", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-fonts-recommended-doc", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-full", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-generic-recommended", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-latex-base", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-latex-base-doc", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-latex-recommended", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-latex-recommended-doc", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-luatex", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-metapost", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-metapost-doc", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-omega", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-pictures", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-pictures-doc", reference:"2014.20141024-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-xetex", reference:"2014.20141024-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
