#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:067. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66081);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/16 19:20:15 $");

  script_cve_id("CVE-2012-5649", "CVE-2012-5650");
  script_bugtraq_id(57314, 57321);
  script_xref(name:"MDVSA", value:"2013:067");
  script_xref(name:"MGASA", value:"2013-0040");

  script_name(english:"Mandriva Linux Security Advisory : couchdb (MDVSA-2013:067)");
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
"Updated couchdb packages fix security vulnerabilities :

A security flaw was found in the way Apache CouchDB, a
distributed,fault- tolerant and schema-free document-oriented database
accessible via a RESTful HTTP/JSON API, processed certain JSON
callback. A remote attacker could provide a specially crafted JSON
callback that, when processed could lead to arbitrary JSON code
execution via Adobe Flash (CVE-2012-5649).

A DOM based cross-site scripting (XSS) flaw was found in the way
browser- based test suite of Apache CouchDB, a distributed,
fault-tolerant and schema-free document-oriented database accessible
via a RESTful HTTP/JSON API, processed certain query parameters. A
remote attacker could provide a specially crafted web page that, when
accessed could lead to arbitrary web script or HTML execution in the
context of a CouchDB user session (CVE-2012-5650)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected couchdb and / or couchdb-bin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:couchdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:couchdb-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"couchdb-1.2.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"couchdb-bin-1.2.1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
