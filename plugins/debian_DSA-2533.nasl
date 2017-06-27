#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2533. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61652);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-3418", "CVE-2012-3419", "CVE-2012-3420", "CVE-2012-3421");
  script_bugtraq_id(55041);
  script_osvdb_id(84797, 84798, 84799, 84800);
  script_xref(name:"DSA", value:"2533");

  script_name(english:"Debian DSA-2533-1 : pcp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Performance Co-Pilot (pcp), a framework for
performance monitoring, contains several vulnerabilities.

  - CVE-2012-3418
    Multiple buffer overflows in the PCP protocol decoders
    can cause PCP clients and servers to crash or,
    potentially, execute arbitrary code while processing
    crafted PDUs.

  - CVE-2012-3419
    The 'linux' PMDA used by the pmcd daemon discloses
    sensitive information from the /proc file system to
    unauthenticated clients.

  - CVE-2012-3420
    Multiple memory leaks processing crafted requests can
    cause pmcd to consume large amounts of memory and
    eventually crash.

  - CVE-2012-3421
    Incorrect event-driven programming allows malicious
    clients to prevent other clients from accessing the pmcd
    daemon.

To address the information disclosure vulnerability, CVE-2012-3419, a
new 'proc' PMDA was introduced, which is disabled by default. If you
need access to this information, you need to enable the 'proc' PMDA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/pcp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pcp packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.3.3-squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libpcp-gui2", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-gui2-dev", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-logsummary-perl", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-mmv-perl", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-mmv1", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-mmv1-dev", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-pmda-perl", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-pmda3", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-pmda3-dev", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-trace2", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp-trace2-dev", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp3", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libpcp3-dev", reference:"3.3.3-squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"pcp", reference:"3.3.3-squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
