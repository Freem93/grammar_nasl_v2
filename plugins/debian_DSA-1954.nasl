#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1954. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44819);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2007-3112", "CVE-2007-3113", "CVE-2009-4032", "CVE-2010-2543");
  script_bugtraq_id(37109);
  script_osvdb_id(37019, 60483, 60564, 60565, 60566);
  script_xref(name:"DSA", value:"1954");

  script_name(english:"Debian DSA-1954-1 : cacti - insufficient input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in cacti, a frontend to
rrdtool for monitoring systems and services. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-3112, CVE-2007-3113
    It was discovered that cacti is prone to a denial of
    service via the graph_height, graph_width, graph_start
    and graph_end parameters. This issue only affects the
    oldstable (etch) version of cacti.

  - CVE-2009-4032
    It was discovered that cacti is prone to several
    cross-site scripting attacks via different vectors.

  - CVE-2009-4112
    It has been discovered that cacti allows authenticated
    administrator users to gain access to the host system by
    executing arbitrary commands via the 'Data Input Method'
    for the 'Linux - Get Memory Usage' setting.

  There is no fix for this issue at this stage. Upstream will
  implement a whitelist policy to only allow certain 'safe' commands.
  For the moment, we recommend that such access is only given to
  trusted users and that the options 'Data Input' and 'User
  Administration' are otherwise deactivated."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=429224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1954"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cacti packages.

For the oldstable distribution (etch), these problems have been fixed
in version 0.8.6i-3.6.

For the stable distribution (lenny), this problem has been fixed in
version 0.8.7b-2.1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cacti", reference:"0.8.6i-3.6")) flag++;
if (deb_check(release:"5.0", prefix:"cacti", reference:"0.8.7b-2.1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
