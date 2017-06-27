#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73966);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2011-1384");
  script_bugtraq_id(51059);
  script_osvdb_id(77688, 77689);

  script_name(english:"IBM Inventory Scout < 2.2.0.19 Symlink Vulnerability");
  script_summary(english:"Sends a 'VERSIONS' action request and checks the response");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a program that could allow a user to delete
or manipulate files without authorization.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Inventory Scout install on
the remote host is a version prior to 2.2.0.19. It, therefore, could
allow a local user to delete arbitrary files or have Inventory Scout
operations operate on arbitrary files using a symlink attack.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/invscout_advisory2.asc");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV11643");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Inventory Scout 2.2.0.19 or later.

Alternatively, remove the setuid bit from the affected files using the
following commands :

  - chmod 555 /opt/IBMinvscout/bin/invscoutClient_VPD_Survey
  - chmod 555 /opt/IBMinvscout/sbin/invscout_lsvpd

Note that this will disable functionality of these commands for all
users except root.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:invscout.rte");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/invscoutd", 808);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"invscoutd", default:808, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


req = 'ACTION=VERSIONS\x00';
send(socket:soc, data:req);
res = recv(socket:soc, length:256, min:256);
close(soc);


if (!substr_at_offset(str:res, blob:'RESULT=0\n\n', offset:0)) audit(AUDIT_RESP_BAD, port, "a 'VERSIONS' action request");

lines = egrep(pattern:"^[0-9]+(\.[0-9]+){3}$", string:res);
versions = split(lines, keep:FALSE);
if (max_index(versions) != 2) audit(AUDIT_RESP_BAD, port, "a 'VERSIONS' action request");

invscoutd_version = versions[0];
logicdb_version = versions[1];
set_kb_item(name:"invscoutd/"+port+"/invscoutd_version", value:invscoutd_version);
set_kb_item(name:"invscoutd/"+port+"/logicdb_version", value:logicdb_version);

fixed_version = "2.2.0.19";
if (ver_compare(ver:invscoutd_version, fix:fixed_version) < 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + invscoutd_version +
             '\n  Fixed version     : ' + fixed_version +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Inventory Scout", port, invscoutd_version);
