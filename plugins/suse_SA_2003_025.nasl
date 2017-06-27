#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(13795);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/27 16:23:24 $");

  script_cve_id("CVE-2003-0201");
  script_bugtraq_id(7294);
  script_osvdb_id(4469);
  script_xref(name:"CERT", value:"267873");
  script_xref(name:"EDB-ID", value:"7");

  script_name(english:"SUSE-SA:2003:025: samba");
  script_summary(english:"Checks the version of the samba package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security patch for samba. It is,
therefore, affected by a buffer overflow condition in the
call_trans2open() function within file trans2.c due to improper
sanitization of user-supplied input. An unauthenticated, remote
attacker can exploit this, via an overly long string passed to the
pname variable, to execute arbitrary code with the privileges of the
server.");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/support/security/advisories/2003_025_samba.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba and samba-client packages according to the
SUSE-SA:2003:025 security announcement.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba trans2open Overflow (Solaris SPARC)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/07");
  script_set_attribute(attribute:"patch_publication_date", value: "2003/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:samba:samba");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^((SLE(S|D)|SUSE)\d+(\.\d+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SUSE7\.1|SUSE7\.2|SUSE7\.3|SUSE8\.0|SUSE8\.1|SUSE8\.2)$", string:os_ver)) 
{
  if ( os_ver =~ "^SUSE" )
  {
    audit(AUDIT_OS_NOT, "SUSE 7.1 / SUSE 7.2 / SUSE 7.3 / SUSE 8.0 / SUSE 8.1 / SUSE 8.2", os_ver);
  }
  else
  {
    audit(AUDIT_OS_NOT, "SUSE 7.1 / SUSE 7.2 / SUSE 7.3 / SUSE 8.0 / SUSE 8.1 / SUSE 8.2", "SUSE " + os_ver);
  }
}
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (rpm_check(release:"SUSE7.1", reference:"samba-2.0.10-32")) flag++;
if (rpm_check(release:"SUSE7.1", reference:"smbclnt-2.0.10-32")) flag++;
if (rpm_check(release:"SUSE7.2", reference:"samba-2.2.0a-52")) flag++;
if (rpm_check(release:"SUSE7.2", reference:"smbclnt-2.2.0a-52")) flag++;
if (rpm_check(release:"SUSE7.3", reference:"samba-2.2.1a-220")) flag++;
if (rpm_check(release:"SUSE7.3", reference:"samba-client-2.2.1a-220")) flag++;
if (rpm_check(release:"SUSE8.0", reference:"samba-2.2.3a-172")) flag++;
if (rpm_check(release:"SUSE8.0", reference:"samba-client-2.2.3a-172")) flag++;
if (rpm_check(release:"SUSE8.1", reference:"samba-2.2.5-178")) flag++;
if (rpm_check(release:"SUSE8.1", reference:"samba-client-2.2.5-178")) flag++;
if (rpm_check(release:"SUSE8.2", reference:"samba-2.2.7a-72")) flag++;
if (rpm_check(release:"SUSE8.2", reference:"samba-client-2.2.7a-72")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
}
else
{
  if (rpm_exists(rpm:"samba-", release:"SUSE7.1")
    || rpm_exists(rpm:"samba-", release:"SUSE7.2")
    || rpm_exists(rpm:"samba-", release:"SUSE7.3")
    || rpm_exists(rpm:"samba-", release:"SUSE8.0")
    || rpm_exists(rpm:"samba-", release:"SUSE8.1")
    || rpm_exists(rpm:"samba-", release:"SUSE8.2") )
  {
    set_kb_item(name:"CVE-2003-0201", value:TRUE);
  }
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / smbclnt");
}
