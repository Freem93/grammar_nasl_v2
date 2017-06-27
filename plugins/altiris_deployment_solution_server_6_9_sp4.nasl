#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45592);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/21 01:44:55 $");

  script_cve_id("CVE-2010-0109");
  script_bugtraq_id(38410);
  script_osvdb_id(62569);
  script_xref(name:"Secunia", value:"38719");

  script_name(english:"Altiris Deployment Solution Server < 6.9 SP4 DBManager DoS (SYM10-007)");
  script_summary(english:"Checks deployment server banner version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a deployment server that is affected by a
denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Altiris Deployment Solution installed on the remote
host is reportedly affected by a denial of service vulnerability. 
The DBManager component has a use-after-free error when processing
specially crafted 'CreateSession' and 'PXEManagerSignOn' requests.

A remote attacker could exploit this to crash the DBManager service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?beb87f98"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Altiris Deployment Solution Server 6.9 SP4 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/25");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/04/20");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/21");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

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
fixed_version = '6.9.453';  # 6.9 SP4
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
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "Altiris Deployment Solution Server version "+version+" is listening on port "+port+" and thus not affected.");

