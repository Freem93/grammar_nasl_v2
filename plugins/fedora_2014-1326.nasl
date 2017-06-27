#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-1326.
#

include("compat.inc");

if (description)
{
  script_id(72223);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 22:14:42 $");

  script_bugtraq_id(65057);
  script_xref(name:"FEDORA", value:"2014-1326");

  script_name(english:"Fedora 19 : perl-MARC-XML-1.0.2-1.fc19 (2014-1326)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bump to 1.0.2 to address XML external entity exploit CVE-2014-1626
(per https://metacpan.org/source/GMCHARLT/MARC-XML-1.0.2/Changes#L3)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/127517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b6c8654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://metacpan.org/source/GMCHARLT/MARC-XML-1.0.2/Changes#L3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-MARC-XML package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-MARC-XML");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"perl-MARC-XML-1.0.2-1.fc19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-MARC-XML");
}
