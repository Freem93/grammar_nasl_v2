#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:259. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42063);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:11:05 $");

  script_cve_id("CVE-2008-1804");
  script_xref(name:"MDVSA", value:"2009:259-1");

  script_name(english:"Mandriva Linux Security Advisory : snort (MDVSA-2009:259-1)");
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
"preprocessors/spp_frag3.c in Sourcefire Snort before 2.8.1 does not
properly identify packet fragments that have dissimilar TTL values,
which allows remote attackers to bypass detection rules by using a
different TTL for each fragment. (CVE-2008-1804)

The updated packages have been patched to prevent this.

Additionally there were problems with two rules in the snort-rules
package for 2008.0 that is also fixed with this update.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-bloat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-inline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-inline+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-mysql+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-plain+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-postgresql+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-prelude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-prelude+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-rules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"snort-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-bloat-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-inline-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-inline+flexresp-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-mysql-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-mysql+flexresp-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-plain+flexresp-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-postgresql-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-postgresql+flexresp-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-prelude-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-prelude+flexresp-2.7.0.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"snort-rules-2.3.3-4.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
