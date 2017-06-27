#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(11562);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2003-1121");
  script_bugtraq_id(7475, 7477);
  script_osvdb_id(15657, 15658);
  script_xref(name:"CERT", value:"231705");

  script_name(english:"ScriptLogic Multiple Service Remote Privilege Escalation");
  script_summary(english:"Checks for the presence of the ScriptLogic service");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service may be vulnerable to an access control breach.'
  );
  script_set_attribute(
    attribute:'description',
    value:
'The ScriptLogic service is running on this port. 

There is a flaw in versions up to 4.05 of this service which may allow
an attacker to write arbitrary values in the remote registry with
administrator privileges, which can be used to gain a shell on this
host. 

*** Since Nessus was unable to determine the version of ScriptLogic
*** running on this host, this might be a false positive.'
  );
  script_set_attribute(attribute:'solution', value:'Upgrade to ScriptLogic 4.15 or later.');
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc." );
  script_family(english:"Windows");
  script_dependencie("smb_enum_services.nasl");
  script_require_keys("SMB/svcs");
  exit(0);
}

#
# The script code starts here
#
port = get_kb_item("SMB/transport");
if(!port)port = 139;


services = get_kb_item("SMB/svcs");
if(services)
{
 if("[SLServer]" >< services)security_hole(port);
}
