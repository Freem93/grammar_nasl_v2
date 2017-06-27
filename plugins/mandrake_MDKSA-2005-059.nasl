#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:059. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(17347);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/08/09 10:54:12 $");

  script_cve_id("CVE-2005-0806");
  script_xref(name:"MDKSA", value:"2005:059");

  script_name(english:"Mandrake Linux Security Advisory : evolution (MDKSA-2005:059)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that certain types of messages could be used to
crash the Evolution mail client. Fixes have been applied to correct
this behaviour."
  );
  # http://bugzilla.ximian.com/show_bug.cgi?id=72609
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ec42699"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected evolution, evolution-devel and / or
evolution-pilot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution-pilot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"evolution-2.0.3-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"evolution-devel-2.0.3-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"evolution-pilot-2.0.3-1.3.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
