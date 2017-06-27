#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-153. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14990);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/07/10 17:04:23 $");

  script_cve_id("CVE-2002-1110", "CVE-2002-1111", "CVE-2002-1112", "CVE-2002-1113", "CVE-2002-1114");
  script_bugtraq_id(5504, 5509, 5510, 5514, 5515, 5563, 5565);
  script_osvdb_id(4858, 6211, 6212, 6213, 6214);
  script_xref(name:"DSA", value:"153");

  script_name(english:"Debian DSA-153-1 : mantis - cross site code execution and privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joao Gouveia discovered an uninitialized variable which was insecurely
used with file inclusions in the mantis package, a php based bug
tracking system. The Debian Security Team found even more similar
problems. When these occasions are exploited, a remote user is able to
execute arbitrary code under the webserver user id on the web server
hosting the mantis system.

Jeroen Latour discovered that Mantis did not check all user input,
especially if they do not come directly from form fields. This opens
up a wide variety of SQL poisoning vulnerabilities on systems without
magic_quotes_gpc enabled. Most of these vulnerabilities are only
exploitable in a limited manner, since it is no longer possible to
execute multiple queries using one call to mysql_query(). There is one
query which can be tricked into changing an account's access level.

Jeroen Latour also reported that it is possible to instruct Mantis to
show reporters only the bugs that they reported, by setting the
limit_reporters option to ON. However, when formatting the output
suitable for printing, the program did not check the limit_reporters
option and thus allowed reporters to see the summaries of bugs they
did not report.

Jeroen Latour discovered that the page responsible for displaying a
list of bugs in a particular project, did not check whether the user
actually has access to the project, which is transmitted by a cookie
variable. It accidentally trusted the fact that only projects
accessible to the user were listed in the drop-down menu. This
provides a malicious user with an opportunity to display the bugs of a
private project selected.

These problems have been fixed in version 0.17.1-2.2 for the current
stable distribution (woody) and in version 0.17.4a-2 for the unstable
distribution (sid). The old stable distribution (potato) is not
affected, since it doesn't contain the mantis package.

Additional information :

  - Mantis Advisory/2002-01
  - Mantis Advisory/2002-02

  - Mantis Advisory/2002-03

  - Mantis Advisory/2002-04

  - Mantis Advisory/2002-05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-01.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-02.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-03.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-04.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-05.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-153"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the mantis packages immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mantis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"mantis", reference:"0.17.1-2.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
