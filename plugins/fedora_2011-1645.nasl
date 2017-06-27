#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-1645.
#

include("compat.inc");

if (description)
{
  script_id(52006);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/20 21:56:30 $");

  script_cve_id("CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2011-0706");
  script_osvdb_id(71608, 71610, 71615, 71616, 71620, 71621, 71622);
  script_xref(name:"FEDORA", value:"2011-1645");

  script_name(english:"Fedora 14 : java-1.6.0-openjdk-1.6.0.0-52.1.9.7.fc14 (2011-1645)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

S6378709, CVE-2010-4465: AWT event dispatch does not support framework
code 

S6854912, CVE-2010-4465: Security issue with the clipboard access in
Applets 

S6878713, CVE-2010-4469: Verifier heap corruption, relating to
backward jsrs 

S6907662, CVE-2010-4465: System clipboard should ensure access
restrictions 

S6927050, CVE-2010-4470: Features set on SchemaFactory not inherited
by Validator 

S6981922, CVE-2010-4448: DNS cache poisoning by untrusted applets 

S6983554, CVE-2010-4450: (launcher) Fix empty user's LD_LIBRARY_PATH
environment variable in the launcher 

S6985453, CVE-2010-4471: Font.createFont may expose some system
properties in exception text 

S6994263, CVE-2010-4472: Untrusted code can replace JRE's XML DSig
Transform or C14N algorithm implementations 

RH677332, CVE-2011-0706: IcedTea multiple signers privilege escalation

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-February/054134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48fd0267"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"java-1.6.0-openjdk-1.6.0.0-52.1.9.7.fc14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk");
}
