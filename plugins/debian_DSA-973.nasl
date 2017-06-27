#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-973. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22839);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2005-3893", "CVE-2005-3894", "CVE-2005-3895");
  script_bugtraq_id(15537);
  script_osvdb_id(21064, 21065, 21066, 21067);
  script_xref(name:"DSA", value:"973");

  script_name(english:"Debian DSA-973-1 : otrs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in otrs, the Open Ticket
Request System, that can be exploited remotely. The Common
Vulnerabilities and Exposures Project identifies the following
problems :

  - CVE-2005-3893
    Multiple SQL injection vulnerabilities allow remote
    attackers to execute arbitrary SQL commands and bypass
    authentication.

  - CVE-2005-3894
    Multiple cross-site scripting vulnerabilities allow
    remote authenticated users to inject arbitrary web
    script or HTML.

  - CVE-2005-3895
    Internally attached text/html mails are rendered as HTML
    when the queue moderator attempts to download the
    attachment, which allows remote attackers to execute
    arbitrary web script or HTML."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=340352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-973"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the otrs package.

The old stable distribution (woody) does not contain OTRS packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.3.2p01-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/22");
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
if (deb_check(release:"3.1", prefix:"otrs", reference:"1.3.2p01-6")) flag++;
if (deb_check(release:"3.1", prefix:"otrs-doc-de", reference:"1.3.2p01-6")) flag++;
if (deb_check(release:"3.1", prefix:"otrs-doc-en", reference:"1.3.2p01-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
