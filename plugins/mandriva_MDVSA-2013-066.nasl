#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:066. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66080);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2012-1969", "CVE-2012-3981", "CVE-2012-4189", "CVE-2012-4197", "CVE-2012-4198", "CVE-2012-4199", "CVE-2012-5883", "CVE-2013-0785", "CVE-2013-0786");
  script_bugtraq_id(54708, 55349, 56385, 56504, 58001, 58060);
  script_xref(name:"MDVSA", value:"2013:066");

  script_name(english:"Mandriva Linux Security Advisory : bugzilla (MDVSA-2013:066)");
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
"Multiple vulnerablilities was identified and fixed in bugzilla :

The get_attachment_link function in Template.pm in Bugzilla 2.x and
3.x before 3.6.10, 3.7.x and 4.0.x before 4.0.7, 4.1.x and 4.2.x
before 4.2.2, and 4.3.x before 4.3.2 does not check whether an
attachment is private before presenting the attachment description
within a public comment, which allows remote attackers to obtain
sensitive description information by reading a comment
(CVE-2012-1969).

Auth/Verify/LDAP.pm in Bugzilla 2.x and 3.x before 3.6.11, 3.7.x and
4.0.x before 4.0.8, 4.1.x and 4.2.x before 4.2.3, and 4.3.x before
4.3.3 does not restrict the characters in a username, which might
allow remote attackers to inject data into an LDAP directory via a
crafted login attempt (CVE-2012-3981).

Cross-site scripting (XSS) vulnerability in Bugzilla 4.1.x and 4.2.x
before 4.2.4, and 4.3.x and 4.4.x before 4.4rc1, allows remote
attackers to inject arbitrary web script or HTML via a field value
that is not properly handled during construction of a tabular report,
as demonstrated by the Version field (CVE-2012-4189).

Bugzilla/Attachment.pm in attachment.cgi in Bugzilla 2.x and 3.x
before 3.6.12, 3.7.x and 4.0.x before 4.0.9, 4.1.x and 4.2.x before
4.2.4, and 4.3.x and 4.4.x before 4.4rc1 allows remote attackers to
read attachment descriptions from private bugs via an obsolete=1
insert action (CVE-2012-4197).

The User.get method in Bugzilla/WebService/User.pm in Bugzilla 3.7.x
and 4.0.x before 4.0.9, 4.1.x and 4.2.x before 4.2.4, and 4.3.x and
4.4.x before 4.4rc1 has a different outcome for a groups request
depending on whether a group exists, which allows remote authenticated
users to discover private group names by observing whether a call
throws an error (CVE-2012-4198).

template/en/default/bug/field-events.js.tmpl in Bugzilla 3.x before
3.6.12, 3.7.x and 4.0.x before 4.0.9, 4.1.x and 4.2.x before 4.2.4,
and 4.3.x and 4.4.x before 4.4rc1 generates JavaScript function calls
containing private product names or private component names in certain
circumstances involving custom-field visibility control, which allows
remote attackers to obtain sensitive information by reading HTML
source code (CVE-2012-4199).

Cross-site scripting (XSS) vulnerability in the Flash component
infrastructure in YUI 2.8.0 through 2.9.0, as used in Bugzilla 3.7.x
and 4.0.x before 4.0.9, 4.1.x and 4.2.x before 4.2.4, and 4.3.x and
4.4.x before 4.4rc1, allows remote attackers to inject arbitrary web
script or HTML via vectors related to swfstore.swf, a similar issue to
CVE-2010-4209 (CVE-2012-5883).

Cross-site scripting (XSS) vulnerability in show_bug.cgi in Bugzilla
before 3.6.13, 3.7.x and 4.0.x before 4.0.10, 4.1.x and 4.2.x before
4.2.5, and 4.3.x and 4.4.x before 4.4rc2 allows remote attackers to
inject arbitrary web script or HTML via the id parameter in
conjunction with an invalid value of the format parameter
(CVE-2013-0785).

The Bugzilla::Search::build_subselect function in Bugzilla 2.x and 3.x
before 3.6.13 and 3.7.x and 4.0.x before 4.0.10 generates different
error messages for invalid product queries depending on whether a
product exists, which allows remote attackers to discover private
product names by using debug mode for a query (CVE-2013-0786).

The updated packages have upgraded to the 4.2.5 version which is not
vulnerable to these issues"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bugzilla and / or bugzilla-contrib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bugzilla-contrib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
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
if (rpm_check(release:"MDK-MBS1", reference:"bugzilla-4.2.5-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"bugzilla-contrib-4.2.5-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
