#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:112. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66124);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2012-2582", "CVE-2012-4600", "CVE-2012-4751");
  script_bugtraq_id(56093);
  script_xref(name:"MDVSA", value:"2013:112");
  script_xref(name:"MGASA", value:"2012-0322");

  script_name(english:"Mandriva Linux Security Advisory : otrs (MDVSA-2013:112)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated otrs package fixes security vulnerabilities :

Multiple cross-site scripting (XSS) vulnerabilities in Open Ticket
Request System (OTRS) Help Desk 2.4.x before 2.4.13, 3.0.x before
3.0.15, and 3.1.x before 3.1.9, and OTRS ITSM 2.1.x before 2.1.5,
3.0.x before 3.0.6, and 3.1.x before 3.1.6, allow remote attackers to
inject arbitrary web script or HTML via an e-mail message body with
(1) a Cascading Style Sheets (CSS) expression property in the STYLE
attribute of an arbitrary element or (2) UTF-7 text in an
HTTP-EQUIV=CONTENT-TYPE META element (CVE-2012-2582).

Cross-site scripting (XSS) vulnerability in Open Ticket Request System
(OTRS) Help Desk 2.4.x before 2.4.14, 3.0.x before 3.0.16, and 3.1.x
before 3.1.10, when Firefox or Opera is used, allows remote attackers
to inject arbitrary web script or HTML via an e-mail message body with
nested HTML tags (CVE-2012-4600).

Cross-site scripting (XSS) vulnerability in Open Ticket Request System
(OTRS) Help Desk 2.4.x before 2.4.15, 3.0.x before 3.0.17, and 3.1.x
before 3.1.11 allows remote attackers to inject arbitrary web script
or HTML via an e-mail message body with whitespace before a
javascript: URL in the SRC attribute of an element, as demonstrated by
an IFRAME element (CVE-2012-4751)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected otrs package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:otrs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"otrs-3.1.11-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
