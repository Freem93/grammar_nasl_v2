#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:251. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(79996);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_bugtraq_id(71558, 71588);
  script_xref(name:"MDVSA", value:"2014:251");

  script_name(english:"Mandriva Linux Security Advisory : rpm (MDVSA-2014:251)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages fix security vulnerabilities :

It was found that RPM wrote file contents to the target installation
directory under a temporary name, and verified its cryptographic
signature only after the temporary file has been written completely.
Under certain conditions, the system interprets the unverified
temporary file contents and extracts commands from it. This could
allow an attacker to modify signed RPM files in such a way that they
would execute code chosen by the attacker during package installation
(CVE-2013-6435).

It was found that RPM could encounter an integer overflow, leading to
a stack-based buffer overflow, while parsing a crafted CPIO header in
the payload section of an RPM file. This could allow an attacker to
modify signed RPM files in such a way that they would execute code
chosen by the attacker during package installation (CVE-2014-8118)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0529.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpmbuild2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpmsign2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64rpm-devel-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64rpm2-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64rpmbuild2-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64rpmsign2-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-rpm-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rpm-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rpm-build-4.9.1.3-4.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rpm-sign-4.9.1.3-4.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
