#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:097. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(54626);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/12/16 15:13:15 $");

  script_cve_id("CVE-2010-0541", "CVE-2011-0188", "CVE-2011-1004", "CVE-2011-1005");
  script_bugtraq_id(40895, 46458, 46460, 46966);
  script_xref(name:"MDVSA", value:"2011:097");

  script_name(english:"Mandriva Linux Security Advisory : ruby (MDVSA-2011:097)");
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
"Multiple vulnerabilities have been identified and fixed in ruby :

Cross-site scripting (XSS) vulnerability in the WEBrick HTTP server in
Ruby allows remote attackers to inject arbitrary web script or HTML
via a crafted URI that triggers a UTF-7 error page (CVE-2010-0541).

The FileUtils.remove_entry_secure method in Ruby allows local users to
delete arbitrary files via a symlink attack (CVE-2011-1004).

The safe-level feature in Ruby allows context-dependent attackers to
modify strings via the Exception#to_s method, as demonstrated by
changing an intended pathname (CVE-2011-1005).

The VpMemAlloc function in bigdecimal.c in the BigDecimal class in
Ruby does not properly allocate memory, which allows context-dependent
attackers to execute arbitrary code or cause a denial of service
(application crash) via vectors involving creation of a large
BigDecimal value within a 64-bit process, related to an integer
truncation issue. (CVE-2011-0188).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"ruby-1.8.7-7p72.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ruby-devel-1.8.7-7p72.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ruby-doc-1.8.7-7p72.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ruby-tk-1.8.7-7p72.4mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"ruby-1.8.7.p249-4.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"ruby-devel-1.8.7.p249-4.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"ruby-doc-1.8.7.p249-4.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"ruby-tk-1.8.7.p249-4.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
