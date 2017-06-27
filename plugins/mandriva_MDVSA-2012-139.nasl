#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:139. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61984);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_bugtraq_id(55072, 55074);
  script_xref(name:"MDVSA", value:"2012:139");

  script_name(english:"Mandriva Linux Security Advisory : postgresql (MDVSA-2012:139)");
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
"Multiple vulnerabilities has been discovered and corrected in
postgresql :

Prevent access to external files/URLs via contrib/xml2's
xslt_process() (Peter Eisentraut). libxslt offers the ability to read
and write both files and URLs through stylesheet commands, thus
allowing unprivileged database users to both read and write data with
the privileges of the database server. Disable that through proper use
of libxslt's security options (CVE-2012-3488). Also, remove
xslt_process()'s ability to fetch documents and stylesheets from
external files/URLs. While this was a documented feature, it was long
regarded as a bad idea. The fix for CVE-2012-3489 broke that
capability, and rather than expend effort on trying to fix it, we're
just going to summarily remove it.

Prevent access to external files/URLs via XML entity references (Noah
Misch, Tom Lane). xml_parse() would attempt to fetch external files or
URLs as needed to resolve DTD and entity references in an XML value,
thus allowing unprivileged database users to attempt to fetch data
with the privileges of the database server. While the external data
wouldn't get returned directly to the user, portions of it could be
exposed in error messages if the data didn't parse as valid XML; and
in any case the mere ability to check existence of a file might be
useful to an attacker (CVE-2012-3489).

This advisory provides the latest versions of PostgreSQL that is not
vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news/1407/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.3/static/release-8-3-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.0/static/release-9-0-9.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg9.0_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq9.0_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecpg9.0_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpq9.0_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-plpgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.0-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
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
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64ecpg9.0_6-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64pq9.0_5-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libecpg9.0_6-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libpq9.0_5-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-contrib-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-devel-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-docs-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-pl-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-plperl-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-plpgsql-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-plpython-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-pltcl-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"postgresql9.0-server-9.0.9-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
