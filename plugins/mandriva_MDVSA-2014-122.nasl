#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:122. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(74480);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/20 15:06:53 $");

  script_cve_id("CVE-2014-0476");
  script_bugtraq_id(67813);
  script_xref(name:"MDVSA", value:"2014:122");

  script_name(english:"Mandriva Linux Security Advisory : chkrootkit (MDVSA-2014:122)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated chkrootkit package fixes security vulnerability :

The chkrootkit script contains a flaw that allows a local attacker to
create an executable in /tmp that will be run by the user running
chkrootkit (usually root), allowing the attacker to escalate
privileges (CVE-2014-0476)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0249.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chkrootkit package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Chkrootkit Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:chkrootkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"chkrootkit-0.49-6.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
