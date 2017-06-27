#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90713);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2014-3576",
    "CVE-2015-0851"
  );
  script_bugtraq_id(
    76134,
    76272
  );
  script_osvdb_id(
    119887,
    125118,
    129952,
    130424,
    135498
  );
  script_xref(name:"CERT", value:"576313");

  script_name(english:"NetIQ Sentinel < 7.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of NetIQ Sentinel.");

  script_set_attribute(attribute:"synopsis", value:
"The NetIQ Sentinel server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Novell NetIQ Sentinel server installed on the remote
host is prior to 7.4.1. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in Apache ActiveMQ in the
    processControlCommand() function within the file
    broker/TransportConnection.java. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet, to cause a denial of service condition.
    (CVE-2014-3576)

  - A flaw exists in the XMLTooling library due to a failure
    to properly handle integer conversion exceptions. An
    unauthenticated, remote attacker can exploit this, via a
    crafted SAML message, to cause a denial of service
    condition. (CVE-2015-0851)

  - A remote code execution vulnerability exists due to
    unsafe deserialize calls of unauthenticated Java objects
    to the Apache Commons Collections (ACC) library. An
    unauthenticated, remote attacker can exploit this, by
    sending a specially crafted serialized Java object via
    the RMI interface, to execute arbitrary code with the
    privileges of the application. (VulnDB 135498)");
  script_set_attribute(attribute:"see_also", value:"https://download.novell.com/Download?buildid=ZEMvbiAk5k8~");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell NetIQ Sentinel version 7.4.1 or later.
Alternatively, contact the vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:sentinel");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("netiq_sentinel_detect.nbin");
  script_require_keys("installed_sw/NetIQ Sentinel");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("audit.inc");

appname = "NetIQ Sentinel";
port = 8443 ;
vuln = FALSE;
install = get_single_install(
  app_name : appname,
  port     : port,
  exit_if_unknown_ver : TRUE
);
ver = install['version'];
rev = install['Revision'];
report = NULL;
fixed_version = "7.4";
fixed_revision = "2512";

if (ver_compare(ver:ver, fix:fixed_version, strict:FALSE) < 0)
{
  vuln = TRUE;
}
else if (ver_compare(ver:ver, fix:fixed_version, strict:FALSE) == 0)
{
  if(ver_compare(ver:rev, fix:fixed_revision, strict:FALSE) < 0)
    vuln = TRUE;
}

if (vuln)
{
  report =
  '\n' +
  '\n Installed Version: ' + ver +
  '\n Installed Revision: ' + rev +
  '\n Fixed Version: ' + fixed_version +
  '\n Fixed Revision: ' + fixed_revision +
  '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, ver);
}
