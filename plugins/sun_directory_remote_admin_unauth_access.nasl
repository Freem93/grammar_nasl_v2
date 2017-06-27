#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32121);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-1995");
  script_bugtraq_id(28941);
  script_osvdb_id(44624);

  script_name(english:"Sun Java System Directory Server bind-dn Remote Privilege Escalation");
  script_summary(english:"Checks the version of Sun Java Directory Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP proxy server is prone to an unauthorized access
attack." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java System Directory Proxy Server running on the
remote host is affected by an unauthorized access vulnerability. 
Specifically, the server fails to properly classify connections in
relation to 'bind_dn' parameter.  Successful exploitation of this
issue might allow an unprivileged user to gain remote administrative
access to the system." );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019128.1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java System Directory Server 6.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 
 script_set_attribute(attribute:"patch_publication_date", value: "2008/04/25");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/01");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");

vendor = get_kb_item("LDAP/" +port+"/vendorName");
if(!vendor)exit(1,"The 'LDAP/"+port+ "/vendorName' KB is missing.");
if("Sun Microsystems, Inc" >!< vendor) exit(0, "The remote directory server on port "+ port +" does not appear to be from Sun Microsystems.");

ver = get_kb_item("LDAP/" + port + "/vendorVersion");
if (!ver) exit(1,"The 'LDAP/"+port+ "/vendorVersion' KB is missing.");

if("Directory Proxy Server" >!< ver) exit(0, "The remote version "+ ver + " on port "+ port + " does not appear to be from Directory Proxy Server.");

if (ereg(pattern:"^Directory Proxy Server 6\.[0-2]($|[^0-9])", string:ver))
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "  ",ver , " is installed on the remote host.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
  exit(0, "'" +ver+ "' on port " + port +" from " + vendor + " is installed and not vulnerable.");
