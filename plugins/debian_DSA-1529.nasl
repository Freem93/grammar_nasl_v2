# This script was automatically generated from Debian Security 
# Advisory DSA-1529. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-1529 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(38955);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-7211", "CVE-2006-7212", "CVE-2006-7213", "CVE-2006-7214", "CVE-2007-2606", "CVE-2007-3181", "CVE-2007-3527", "CVE-2007-4664", "CVE-2007-4665", "CVE-2007-4666", "CVE-2007-4667", "CVE-2007-4668", "CVE-2007-4669", "CVE-2008-0387", "CVE-2008-0467");
  script_xref(name:"DSA", value:"1529");

  script_name(english:"Debian DSA-1529-1 : firebird -- multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security problems have been discovered in the Firebird
database, which may lead to the execution of arbitrary code or denial
of service. 

This Debian security advisory is a bit unusual.  While it\'s normally
our strict policy to backport security bugfixes to older releases,
this turned out to be infeasible for Firebird 1.5 due to large
infrastructural changes necessary to fix these issues.  As a
consequence security support for Firebird 1.5 is hereby discontinued."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1529"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to the firebird2.0 packages available at backports.org. 
Version 2.0.3.12981.ds1-6~bpo40+1 fixes all known issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2008-2016 Tenable Network Security, Inc.");
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
ref = "1.9.9-9sarge1";                  # nb: any high value should work.
if (deb_check(release:"3.1", prefix:"firebird2-classic-server", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-dev", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-examples", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-server-common", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-super-server", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-utils-classic", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-utils-super", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"libfirebird2-classic", reference:ref)) flag++;
if (deb_check(release:"3.1", prefix:"libfirebird2-super", reference:ref)) flag++;

if (flag)
{
  if (report_verbosity > 0) 
  {
    report = "";
    foreach line (split(deb_report_get(), keep:FALSE))
    {
      if (max >!< line && "Should be :" >!< line) report += line + '\n';
    }
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
