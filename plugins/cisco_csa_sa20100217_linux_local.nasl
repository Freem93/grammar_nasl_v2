#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69951);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2010-0148");
  script_bugtraq_id(38273);
  script_osvdb_id(62445);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtb89870");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100217-csa");

  script_name(english:"Cisco Security Agent 5.2 DoS (cisco-sa-20100217-csa)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an endpoint security application installed that is
potentially affected by a denial of service (DoS) vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Security Agent installed on the remote host is
affected by an unspecified denial of service (DoS) vulnerability.  A
remote, unauthenticated attacker can take advantage of this issue by
sending specially crafted TCP packets to the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20100217-csa.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Security Agent 5.2.0.296 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/RedHat/release");
if (isnull(release)) release = get_kb_item("Host/CentOS/release");

if (isnull(release)) audit(AUDIT_OS_NOT, "Red Hat or CentOS");

if ("Red Hat" >< release)
{
  os = "RedHat";
  rel = "Red Hat";
}
else
{
  os = "CentOS";
  rel = os;
}

rpms = get_kb_item("Host/"+os+"/rpm-list");
if (isnull(rpms)) audit(AUDIT_PACKAGE_LIST_MISSING);

matches = egrep(pattern:"CSAagent-([0-9\.-]+)",string:rpms);
if (!matches) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cisco Security Agent");

non_vuln = make_list();

foreach match (split(matches, keep:FALSE))
{
  fix = '';
  package = eregmatch(pattern:"(CSAagent)-([0-9\.-]+)",string:match);

  if(!isnull(package))
  {
    my_rpm = package[0];
    ver = package[2];
    if ("-" >< ver) ver = ereg_replace(pattern:"-", replace:".", string:ver);

    # Only Cisco Security Agent release 5.2 is affected by the DoS vuln
    if (ver =~ "^5\.2\." && ver_compare(ver:ver, fix:"5.2.285") < 0)
    {
      fix = "CSAagent-5.2-296";
      rpm_report_add(package:my_rpm, reference:"CSAagent-5.2-296");
    }
    else non_vuln = make_list(non_vuln,my_rpm);
  }
}

report = rpm_report_get();
if (!isnull(report))
{
  if (report_verbosity > 0)
  {
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else
{
  rpm_packages = max_index(non_vuln);
  if (rpm_packages ==1)  audit(AUDIT_PACKAGE_NOT_AFFECTED, non_vuln[0]);
  else exit(0, "None of the Cisco Security Agent packages (" + join(non_vuln, sep:", ") + ") are affected.");
}
