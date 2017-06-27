#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:205. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(50008);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/02/07 11:46:01 $");

  script_cve_id("CVE-2010-2445");
  script_bugtraq_id(40598);
  script_xref(name:"MDVSA", value:"2010:205");

  script_name(english:"Mandriva Linux Security Advisory : freeciv (MDVSA-2010:205)");
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
"A vulnerability was discovered and corrected in freeciv :

freeciv 2.2 before 2.2.1 and 2.3 before 2.3.0 allows attackers to read
arbitrary files or execute arbitrary commands via scenario that
contains Lua functionality, related to the (1) os, (2) io, (3)
package, (4) dofile, (5) loadfile, (6) loadlib, (7) module, and (8)
require modules or functions (CVE-2010-2445).

The updated packages have been upgraded to v2.2.1 which is not
vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected freeciv-client, freeciv-data and / or
freeciv-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeciv-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeciv-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeciv-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", reference:"freeciv-client-2.2.1-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"freeciv-data-2.2.1-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"freeciv-server-2.2.1-0.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"freeciv-client-2.2.1-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"freeciv-data-2.2.1-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"freeciv-server-2.2.1-0.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
