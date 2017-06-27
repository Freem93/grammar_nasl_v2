# This script was generated from Debian Security Advisory DSA-177. 
# It is released under the Nessus Script Licence.
#
# Debian Security Advisory DSA-177 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(15014);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2012/01/23 19:09:35 $");

  script_cve_id("CVE-2002-1227");
  script_bugtraq_id(5994);
  script_osvdb_id(5003);
  script_xref(name:"DSA", value:"177");

  script_name(english:"Debian DSA-177-1 : pam -- serious security violation");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A serious security violation in PAM was discovered.  Disabled
passwords (i.e.  those with '*' in the password file) were classified
as empty password and access to such accounts is granted through the
regular login procedure (getty, telnet, ssh).  This works for all such
accounts whose shell field in the password file does not refer to
/bin/false.  Only version 0.76 of PAM seems to be affected by this
problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-177"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pam package.

This problem has been fixed in version 0.76-6 for the current unstable
distribution (sid).  The stable distribution (woody), the old stable
distribution (potato) and the testing distribution (sarge) are not
affected by this problem. 

As stated in the Debian security team FAQ, testing and unstable are
rapidly moving targets and the security team does not have the
resources needed to properly support those.  This security advisory is
an exception to that rule, due to the seriousness of the problem."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2004-2012 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Debian/release")) exit(0, "The host is not running Debian.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");


flag = 0;
if (deb_check(release:"3.2", prefix:"libpam-cracklib", reference:"0.76-6")) flag++;
if (deb_check(release:"3.2", prefix:"libpam-doc", reference:"0.76-6")) flag++;
if (deb_check(release:"3.2", prefix:"libpam-modules", reference:"0.76-6")) flag++;
if (deb_check(release:"3.2", prefix:"libpam-runtime", reference:"0.76-6")) flag++;
if (deb_check(release:"3.2", prefix:"libpam0g", reference:"0.76-6")) flag++;
if (deb_check(release:"3.2", prefix:"libpam0g-dev", reference:"0.76-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
