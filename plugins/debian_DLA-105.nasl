#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-105-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82089);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-9157");
  script_bugtraq_id(71283);

  script_name(english:"Debian DLA-105-1 : graphviz security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joshua Rogers discovered a format string vulnerability in the yyerror
function in lib/cgraph/scan.l in Graphviz, a rich set of graph drawing
tools. An attacker could use this flaw to cause graphviz to crash or
possibly execute arbitrary code.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/graphviz"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcdt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcgraph5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraph4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphviz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvc5-plugins-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvpr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpathplan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxdot4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"graphviz", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"graphviz-dev", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"graphviz-doc", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libcdt4", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libcgraph5", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgraph4", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgraphviz-dev", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-guile", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-lua", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-ocaml", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-perl", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-php5", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-python", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-ruby", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgv-tcl", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgvc5", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgvc5-plugins-gtk", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgvpr1", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpathplan4", reference:"2.26.3-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libxdot4", reference:"2.26.3-5+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
