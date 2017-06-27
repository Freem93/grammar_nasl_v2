#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69863);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2009-3900");
  script_bugtraq_id(36931);
  script_osvdb_id(59778);

  script_name(english:"AIX PowerHA Cluster Management Unspecified Remote Configuration Manipulation");
  script_summary(english:"Check cluster.es.server.diag fileset level");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An unspecified vulnerability in the IBM PowerHA Cluster Management
monitoring of port 6177 could allow a remote attacker to make
unauthorized changes the remote host's AIX configuration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/haport_advisory.asc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ61325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ61323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ62630"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AIX/version", "Host/AIX/lslpp");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("aix.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (!get_kb_item("Host/AIX/version")) audit(AUDIT_OS_NOT, "AIX");

packages = get_kb_item("Host/AIX/lslpp");
if (!packages) audit(AUDIT_PACKAGE_LIST_MISSING);


fileset = "cluster.es.server.diag";


match = eregmatch(pattern:fileset+":([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", string:packages);
if (isnull(match)) exit(0, "The '"+fileset+"' fileset is not installed.");

installed_version = match[1];


flag = 0;

if (installed_version =~ "^5\.4\.0\.")
{
  fixed_version = "5.4.0.3";
  if (vers_cmp(installed_version, fixed_version) < 0)
  {
    aix_report_add(installed:fileset+":"+installed_version, required:'n/a');
    flag++;
  }
}
else if (installed_version =~ "^5\.4\.1\.")
{
  fixed_version = "5.4.1.7";
  if (vers_cmp(installed_version, fixed_version) < 0)
  {
    aix_report_add(installed:fileset+":"+installed_version, required:fileset+"."+fixed_version);
    flag++;
  }
}
else if (installed_version =~ "^5\.5.0\.")
{
  fixed_version = "5.5.0.3";
  if (vers_cmp(installed_version, fixed_version) < 0)
  {
    aix_report_add(installed:fileset+":"+installed_version, required:fileset+"."+fixed_version);
    flag++;
  }
}
else if (installed_version =~ "^6\.1\.0\.")
{
  fixed_version = "6.1.0.1";
  if (vers_cmp(installed_version, fixed_version) < 0)
  {
    aix_report_add(installed:fileset+":"+installed_version, required:fileset+"."+fixed_version);
    flag++;
  }
}
else exit(0, "The high-level version of the '"+fileset+"' fileset is not listed as affected.");


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Fileset '"+fileset+"'", installed_version);
