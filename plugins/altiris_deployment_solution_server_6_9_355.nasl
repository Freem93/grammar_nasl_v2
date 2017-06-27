#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34964);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-6828");
  script_bugtraq_id(31767);
  script_osvdb_id(54976);
  script_xref(name:"Secunia", value:"31773");

  script_name(english:"Altiris Deployment Solution Server < 6.9.355 Password Disclosure (SYM08-020)");
  script_summary(english:"Checks deployment server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by a password
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Altiris Deployment Solution installed on the remote
host reportedly is affected by a password disclosure vulnerability. 
Altiris Deployment Solution Server reportedly stores 'Application
Identity Account password' in the system memory in plain-text.  It may
be possible for an authorized non-privileged user to retrieve this
password and make unauthorized modifications to the client systems. 
The level of unauthorized access depends on the user group under which
Application Identity Account was registered during installation" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.10.20b.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Altiris Deployment Solution 6.9 Build 355 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/25");
 script_cvs_date("$Date: 2016/05/04 14:21:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("altiris_deployment_server_detect.nasl");
  script_require_ports("Services/axengine", 402);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/axengine");
if (!port)
  exit(1, "The 'Services/axengine' KB item is missing.");
if (!get_port_state(port))
  exit(0, "Port "+port+" is not open.");

# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");
close(soc);

# Check the version.
version = get_kb_item("Altiris/DSVersion/"+port);
if (isnull(version))
  exit(1, "The 'Altiris/DSVersion/"+port+"' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("6.9.355", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity)
    {
      version = string(ver[0], ".", ver[1], " Build ", ver[2]);
      report = string(
        "\n",
        "Version ", version, " of the Altiris Deployment Solution is installed on\n",
        "the remote host.\n"
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
  else if (ver[i] > fix[i])
    break;

# If we made it out of the loop, the version is up-to-date
exit(0, "The host is not affected on port "+port+".");

