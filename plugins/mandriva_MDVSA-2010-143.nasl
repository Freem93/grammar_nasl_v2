#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:143. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48209);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/17 17:02:54 $");

  script_cve_id("CVE-2010-2547");
  script_bugtraq_id(41945);
  script_xref(name:"MDVSA", value:"2010:143");

  script_name(english:"Mandriva Linux Security Advisory : gnupg2 (MDVSA-2010:143)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered and corrected in gnupg2 :

Importing a certificate with more than 98 Subject Alternate Names via
GPGSM's import command or implicitly while verifying a signature
causes GPGSM to reallocate an array with the names. The bug is that
the reallocation code misses assigning the reallocated array to the
old array variable and thus the old and freed array will be used.
Usually this leads to a segv (CVE-2010-2547).

Packages for 2008.0 and 2009.0 are provided as of the Extended
Maintenance Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnupg-announce/2010q3/000302.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnupg2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"gnupg2-2.0.5-3.1mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"gnupg2-2.0.9-3.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"gnupg2-2.0.11-1.4mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"gnupg2-2.0.13-1.5mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"gnupg2-2.0.15-11.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
