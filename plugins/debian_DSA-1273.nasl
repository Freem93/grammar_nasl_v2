#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1273. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24921);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1543", "CVE-2007-1544", "CVE-2007-1545", "CVE-2007-1546", "CVE-2007-1547");
  script_bugtraq_id(23017);
  script_osvdb_id(34258, 34259, 34260, 34261, 34262);
  script_xref(name:"DSA", value:"1273");

  script_name(english:"Debian DSA-1273-1 : nas - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in nas, the Network Audio
System.

  - CVE-2007-1543
    A stack-based buffer overflow in the accept_att_local
    function in server/os/connection.c in nas allows remote
    attackers to execute arbitrary code via a long path
    slave name in a USL socket connection.

  - CVE-2007-1544
    An integer overflow in the ProcAuWriteElement function
    in server/dia/audispatch.c allows remote attackers to
    cause a denial of service (crash) and possibly execute
    arbitrary code via a large max_samples value.

  - CVE-2007-1545
    The AddResource function in server/dia/resource.c allows
    remote attackers to cause a denial of service (server
    crash) via a nonexistent client ID.

  - CVE-2007-1546
    An array index error allows remote attackers to cause a
    denial of service (crash) via (1) large num_action
    values in the ProcAuSetElements function in
    server/dia/audispatch.c or (2) a large inputNum
    parameter to the compileInputs function in
    server/dia/auutil.c.

  - CVE-2007-1547
    The ReadRequestFromClient function in server/os/io.c
    allows remote attackers to cause a denial of service
    (crash) via multiple simultaneous connections, which
    triggers a NULL pointer dereference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=416038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1273"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nas package.

For the stable distribution (sarge), these problems have been fixed in
version 1.7-2sarge1.

For the upcoming stable distribution (etch) and the unstable
distribution (sid) these problems have been fixed in version 1.8-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nas");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libaudio-dev", reference:"1.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libaudio2", reference:"1.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"nas", reference:"1.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"nas-bin", reference:"1.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"nas-doc", reference:"1.7-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
