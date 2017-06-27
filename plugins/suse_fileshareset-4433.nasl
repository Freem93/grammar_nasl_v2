#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29429);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2007-4224", "CVE-2007-4569");

  script_name(english:"SuSE 10 Security Update : KDE (ZYPP Patch Number 4433)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Users could log in as root without having to enter the password if
auto login was enabled and if kdm was configured to require the root
passwort to shutdown the system. (CVE-2007-4569)

JavaScript code could modify the URL in the address bar to make the
currently displayed website appear to come from a different site.
(CVE-2007-4224)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4569.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4433.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"fileshareset-2.0-84.57")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-beagle-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-devel-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-kdm-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-ksysguardd-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-nsplugin-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-samba-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-session-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdelibs3-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdelibs3-arts-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdelibs3-devel-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdelibs3-doc-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kdebase3-32bit-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kdelibs3-32bit-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kdelibs3-arts-32bit-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"fileshareset-2.0-84.57")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-devel-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-extra-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-kdm-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-ksysguardd-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-nsplugin-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-samba-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-session-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdelibs3-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdelibs3-arts-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdelibs3-devel-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdelibs3-doc-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kdebase3-32bit-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kdebase3-nsplugin64-3.5.1-69.58")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kdelibs3-32bit-3.5.1-49.39")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kdelibs3-arts-32bit-3.5.1-49.39")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
