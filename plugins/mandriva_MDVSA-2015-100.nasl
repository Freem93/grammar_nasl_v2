#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:100. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82353);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2013-6473", "CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476", "CVE-2014-2707", "CVE-2014-4336", "CVE-2014-4337", "CVE-2014-4338");
  script_xref(name:"MDVSA", value:"2015:100");

  script_name(english:"Mandriva Linux Security Advisory : cups-filters (MDVSA-2015:100)");
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
"Updated cups-filters packages fix security vulnerabilities :

Florian Weimer discovered that cups-filters incorrectly handled memory
in the urftopdf filter. An attacker could possibly use this issue to
execute arbitrary code with the privileges of the lp user
(CVE-2013-6473).

Florian Weimer discovered that cups-filters incorrectly handled memory
in the pdftoopvp filter. An attacker could possibly use this issue to
execute arbitrary code with the privileges of the lp user
(CVE-2013-6474, CVE-2013-6475).

Florian Weimer discovered that cups-filters did not restrict driver
directories in in the pdftoopvp filter. An attacker could possibly use
this issue to execute arbitrary code with the privileges of the lp
user (CVE-2013-6476).

Sebastian Krahmer discovered it was possible to use malicious
broadcast packets to execute arbitrary commands on a server running
the cups-browsed daemon (CVE-2014-2707).

In cups-filters before 1.0.53, out-of-bounds accesses in the
process_browse_data function when reading the packet variable could
leading to a crash, thus resulting in a denial of service
(CVE-2014-4337).

In cups-filters before 1.0.53, if there was only a single BrowseAllow
line in cups-browsed.conf and its host specification was invalid, this
was interpreted as if no BrowseAllow line had been specified, which
resulted in it accepting browse packets from all hosts
(CVE-2014-4338).

The CVE-2014-2707 issue with malicious broadcast packets, which had
been fixed in Mageia Bug 13216 (MGASA-2014-0181), had not been
completely fixed by that update. A more complete fix was implemented
in cups-filters 1.0.53 (CVE-2014-4336).

Note that only systems that have enabled the affected feature by using
the CreateIPPPrinterQueues configuration directive in
/etc/cups/cups-browsed.conf were affected by the CVE-2014-2707 /
CVE-2014-4336 issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0267.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected cups-filters, lib64cups-filters-devel and / or
lib64cups-filters1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups-filters1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"cups-filters-1.0.53-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64cups-filters-devel-1.0.53-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64cups-filters1-1.0.53-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
