#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:122. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61972);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/01 13:30:48 $");

  script_cve_id("CVE-2012-3422", "CVE-2012-3423");
  script_bugtraq_id(54762);
  script_xref(name:"MDVSA", value:"2012:122");

  script_name(english:"Mandriva Linux Security Advisory : icedtea-web (MDVSA-2012:122)");
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
icedtea-web :

An uninitialized pointer use flaw was found in IcedTea-Web web browser
plugin. A malicious web page could use this flaw make IcedTea-Web
browser plugin pass invalid pointer to a web browser. Depending on the
browser used, it may cause the browser to crash or possibly execute
arbitrary code (CVE-2012-3422).

It was discovered that the IcedTea-Web web browser plugin incorrectly
assumed that all strings provided by browser are NUL terminated, which
is not guaranteed by the NPAPI (Netscape Plugin Application
Programming Interface). When used in a browser that does not NUL
terminate NPVariant NPStrings, this could lead to buffer over-read or
over-write, resulting in possible information leak, crash, or code
execution (CVE-2012-3423).

The updated packages have been upgraded to the 1.1.6 version which is
not affected by these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web and / or icedtea-web-javadoc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"icedtea-web-1.1.6-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"icedtea-web-javadoc-1.1.6-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
