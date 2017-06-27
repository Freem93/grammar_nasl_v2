#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:056. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(58717);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");
  script_bugtraq_id(52865);
  script_xref(name:"MDVSA", value:"2012:056");

  script_name(english:"Mandriva Linux Security Advisory : rpm (MDVSA-2012:056)");
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
"Multiple flaws were found in the way RPM parsed package file headers.
An attacker could create a specially crafted RPM package that, when
its package header was accessed, or during package signature
verification, could cause an application using the RPM library to
crash or, potentially, execute arbitrary code (CVE-2012-0060,
CVE-2012-0061, CVE-2012-0815).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=744104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=744858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=798585"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpm4.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librpm4.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64rpm-devel-4.6.0-14.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64rpm4.6-4.6.0-14.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"librpm-devel-4.6.0-14.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"librpm4.6-4.6.0-14.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"python-rpm-4.6.0-14.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"rpm-4.6.0-14.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"rpm-build-4.6.0-14.3mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
