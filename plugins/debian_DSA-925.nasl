#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-925. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22791);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2005-3310", "CVE-2005-3415", "CVE-2005-3416", "CVE-2005-3417", "CVE-2005-3418", "CVE-2005-3419", "CVE-2005-3420", "CVE-2005-3477", "CVE-2005-3536", "CVE-2005-3537", "CVE-2005-3975", "CVE-2005-4426");
  script_bugtraq_id(15170, 15243);
  script_osvdb_id(20248, 20386, 20387, 20388, 20389, 20390, 20391, 20413, 20414, 22270, 22271);
  script_xref(name:"DSA", value:"925");

  script_name(english:"Debian DSA-925-1 : phpbb2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in phpBB, a fully
featured and skinnable flat webforum. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2005-3310
    Multiple interpretation errors allow remote
    authenticated users to inject arbitrary web script when
    remote avatars and avatar uploading are enabled.

  - CVE-2005-3415
    phpBB allows remote attackers to bypass protection
    mechanisms that deregister global variables that allows
    attackers to manipulate the behaviour of phpBB.

  - CVE-2005-3416
    phpBB allows remote attackers to bypass security checks
    when register_globals is enabled and the session_start
    function has not been called to handle a session.

  - CVE-2005-3417
    phpBB allows remote attackers to modify global variables
    and bypass security mechanisms.

  - CVE-2005-3418
    Multiple cross-site scripting (XSS) vulnerabilities
    allow remote attackers to inject arbitrary web scripts.

  - CVE-2005-3419
    A SQL injection vulnerability allows remote attackers to
    execute arbitrary SQL commands.

  - CVE-2005-3420
    phpBB allows remote attackers to modify regular
    expressions and execute PHP code via the
    signature_bbcode_uid parameter.

  - CVE-2005-3536
    Missing input sanitising of the topic type allows remote
    attackers to inject arbitrary SQL commands.

  - CVE-2005-3537
    Missing request validation permitted remote attackers to
    edit private messages of other users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=35662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=336582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=336587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-925"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpbb2 packages.

The old stable distribution (woody) does not contain phpbb2 packages.

For the stable distribution (sarge) these problems have been fixed in
version 2.0.13+1-6sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpbb2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/22");
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
if (deb_check(release:"3.1", prefix:"phpbb2", reference:"2.0.13-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpbb2-conf-mysql", reference:"2.0.13-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpbb2-languages", reference:"2.0.13-6sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
