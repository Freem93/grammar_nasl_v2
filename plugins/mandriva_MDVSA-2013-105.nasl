#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:105. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66117);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/20 10:48:34 $");

  script_cve_id("CVE-2012-2103", "CVE-2012-3512", "CVE-2012-3513");
  script_bugtraq_id(53031, 55698, 56398);
  script_xref(name:"MDVSA", value:"2013:105");
  script_xref(name:"MGASA", value:"2012-0358");

  script_name(english:"Mandriva Linux Security Advisory : munin (MDVSA-2013:105)");
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
"Updated munin packages fix security vulnerabilities :

The qmailscan plugin for Munin before 2.0 rc6 allows local users to
overwrite arbitrary files via a symlink attack on temporary files with
predictable names (CVE-2012-2103).

Munin before 2.0.6 stores plugin state files that run as root in the
same group-writable directory as non-root plugins, which allows local
users to execute arbitrary code by replacing a state file, as
demonstrated using the smart_ plugin (CVE-2012-3512).

munin-cgi-graph in Munin before 2.0.6, when running as a CGI module
under Apache, allows remote attackers to load new configurations and
create files in arbitrary directories via the logdir command
(CVE-2012-3513)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected munin, munin-master and / or munin-node packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:munin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:munin-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:munin-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
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
if (rpm_check(release:"MDK-MBS1", reference:"munin-2.0-0.rc5.3.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"munin-master-2.0-0.rc5.3.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"munin-node-2.0-0.rc5.3.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
