#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43828);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2009-3107",
    "CVE-2009-3108",
    "CVE-2009-3109",
    "CVE-2009-3110"
  );
  script_bugtraq_id(36110, 36111, 36112, 36113);
  script_osvdb_id(57458, 57459, 57460, 57461);
  script_xref(name:"Secunia", value:"36502");

  script_name(english:"Altiris Deployment Solution Server < 6.9.430 Multiple Vulnerabilities (SYM09-011)");
  script_summary(english:"Checks deployment server version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a deployment server that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Altiris Deployment Solution installed on the remote
host is reportedly affected by the following vulnerabilities :

  - DBManager authentication can by bypassed.  A remote
    attacker could exploit this to execute arbitrary database
    queries. (CVE-2009-3107)

  - The Aclient GUI has a privilege escalation vulnerability.
    This could allow an unprivileged user to compromise the
    client. (CVE-2009-3108)

  - When key-based authentication is being used, it is possible
    to issue commands to an agent before the handshake is
    completed.  A malicious server could exploit this to execute
    arbitrary commands as SYSTEM. (CVE-2009-3109)

  - Due to a race condition, a malicious user could intercept
    a file transfer meant for a legitimate client.  This could
    result in the disclosure of sensitive information, or a denial
    of service. (CVE-2009-3110)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54b8b8c5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f5eb693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f86b6943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c95b198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f914235e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Altiris Deployment Solution Server 6.9.430 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 362);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/26"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/26"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2010/01/08"
  );
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("altiris_deployment_server_detect.nasl");
  script_require_ports("Services/axengine");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/axengine");
if (!port)
  exit(1, "The 'Services/axengine' KB item is missing.");
if (!get_port_state(port))
  exit(0, "Port "+port+" is not open.");

# Check the version.
fixed_version = '6.9.430';
version = get_kb_item("Altiris/DSVersion/" + port);
if (isnull(version))
  exit(1, "The 'Altiris/DSVersion/"+port+"' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
fix = split(fixed_version, sep:'.', keep:FALSE);
vuln = FALSE;

for (i = 0; i < max_index(ver) && !vuln; i++)
{
  if (int(ver[i]) < int(fix[i])) vuln = TRUE;
  else if (int(ver[i]) > int(fix[i])) break;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : '+version+
      '\n  Fixed version      : '+fixed_version+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Altiris Deployment Solution Server version "+version+" is listening on port "+port+" and thus not affected.");

